from __future__ import annotations

import binascii
import hashlib
import hmac
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_warrant.canonical import canonicalize
from agent_warrant.encoding import b64u, b64u_decode
from agent_warrant.identity import decode_public_key, encode_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROOF_DOMAIN = b"agentic-security-reference/effect-proof/v1\x00"
CREDENTIAL_VERSION = 1


def read_private_file(path: Path, label: str) -> bytes:
    """Read a file the executor owns: regular, not a symlink, owned by this user, no group or other access."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as err:
        raise ValueError(f"cannot open {label} {path}: {err}") from err
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} {path} is not a regular file")
        if info.st_uid != os.geteuid():
            raise ValueError(f"{label} {path} is not owned by the current user")
        if info.st_mode & 0o077:
            raise ValueError(f"{label} {path} must be mode 0600, found {stat.S_IMODE(info.st_mode):04o}")
        return os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)


class FileSecretStore:
    """Secrets loaded once at startup from a directory of 0600 files, one file per secret name. `get` raises
    KeyError for a name that was not loaded; there is no default."""

    def __init__(self, directory: Path) -> None:
        self._secrets: dict[str, bytes] = {}
        for entry in sorted(directory.iterdir()):
            self._secrets[entry.name] = read_private_file(entry, f"secret {entry.name}")

    def get(self, name: str) -> bytes:
        return self._secrets[name]

    def names(self) -> frozenset[str]:
        return frozenset(self._secrets)


class EmptySecretStore:
    """For processes that must hold no secrets, such as the operator."""

    def get(self, name: str) -> bytes:
        raise KeyError(name)


def load_executor_key(path: Path) -> Ed25519PrivateKey:
    seed = b64u_decode(read_private_file(path, "executor key").decode().strip())
    return Ed25519PrivateKey.from_private_bytes(seed)


def write_executor_key(path: Path, key: Ed25519PrivateKey) -> None:
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, b64u(seed).encode())
    finally:
        os.close(descriptor)


def executor_key_id(key: Ed25519PrivateKey) -> str:
    return encode_public_key(key.public_key())


def _mac(secret: bytes, body: dict[str, Any]) -> str:
    return b64u(hmac.new(secret, canonicalize(body), hashlib.sha256).digest())


class HmacMinter:
    """Turns a long-lived target secret into a short-lived credential for one operation. The credential names
    the executor key (kid), the audience, and the digest of the whole operation (rd); the target verifies the MAC
    with its own copy of the secret."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock

    def mint(
        self, secret: bytes, executor_key_id: str, audience: str, request_digest: str, ttl: float
    ) -> dict[str, Any]:
        body = {
            "v": CREDENTIAL_VERSION,
            "kid": executor_key_id,
            "aud": audience,
            "rd": request_digest,
            "exp": int(self._clock() + ttl),
        }
        return {**body, "mac": _mac(secret, body)}


def verify_credential_mac(secret: bytes, credential: dict[str, Any]) -> bool:
    try:
        body = {name: credential[name] for name in ("v", "kid", "aud", "rd", "exp")}
        provided = credential["mac"]
        if set(credential) != {*body, "mac"} or not isinstance(provided, str):
            return False
        return hmac.compare_digest(_mac(secret, body), provided)
    except (KeyError, TypeError, ValueError):
        return False


def sign_effect_proof(key: Ed25519PrivateKey, credential: dict[str, Any]) -> str:
    """Executor's possession proof over one credential. A copied credential is useless without the executor key."""
    message = PROOF_DOMAIN + credential["mac"].encode() + b"|" + credential["rd"].encode()
    return b64u(key.sign(message))


def verify_effect_proof(key_id: str, credential: dict[str, Any], proof: str) -> bool:
    try:
        message = PROOF_DOMAIN + credential["mac"].encode() + b"|" + credential["rd"].encode()
        decode_public_key(key_id).verify(b64u_decode(proof), message)
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error, AttributeError):
        return False
