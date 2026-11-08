from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from agent_warrant.ledger import Operation

from .credentials import verify_credential_mac, verify_effect_proof
from .protocol import args_digest


class TargetRefused(Exception):
    """The target definitely did not perform the effect."""


class TargetUnavailable(Exception):
    """The target could not be reached or did not answer; the effect may or may not have happened."""


@dataclass(frozen=True)
class EffectCall:
    credential: dict[str, Any]
    proof: str
    operation: dict[str, Any]
    args: dict[str, Any]


class Target(Protocol):
    tools: frozenset[str]

    def perform(self, call: EffectCall) -> dict[str, Any]: ...


class SecuredTarget:
    """A fake effect target that accepts an injected credential only. It holds its own copy of the secret and
    the executor's public key id. A call is accepted when: the MAC verifies; the audience is this target; the
    credential has not expired; the key id is the pinned executor key; the proof is the executor key's signature
    over this credential; the credential's digest equals the digest of the operation presented, so it works for
    that exact operation only; the arguments match the operation; and the operation id was not used before.
    Subclasses implement `apply`."""

    def __init__(
        self,
        name: str,
        audience: str,
        secret: bytes,
        executor_key_id: str,
        tools: Iterable[str],
        clock: Callable[[], float],
        log_path: Path | None = None,
    ) -> None:
        self.name = name
        self.tools = frozenset(tools)
        self._audience = audience
        self._secret = secret
        self._executor_key_id = executor_key_id
        self._clock = clock
        self._used: set[str] = set()
        self._log_path = log_path
        self.effects: list[dict[str, Any]] = []

    def perform(self, call: EffectCall) -> dict[str, Any]:
        credential = call.credential
        if not verify_credential_mac(self._secret, credential):
            raise TargetRefused("credential not issued for this target")
        if credential["aud"] != self._audience:
            raise TargetRefused("credential audience is not this target")
        if self._clock() >= credential["exp"]:
            raise TargetRefused("credential expired")
        if credential["kid"] != self._executor_key_id:
            raise TargetRefused("credential holder is not the pinned executor key")
        if not verify_effect_proof(self._executor_key_id, credential, call.proof):
            raise TargetRefused("holder proof invalid")
        try:
            operation = Operation(**call.operation)
        except TypeError:
            raise TargetRefused("operation malformed") from None
        if operation.digest() != credential["rd"]:
            raise TargetRefused("credential was issued for a different operation")
        if operation.args_digest != args_digest(call.args):
            raise TargetRefused("arguments differ from the operation")
        if operation.tool not in self.tools:
            raise TargetRefused(f"tool {operation.tool!r} is not served here")
        if operation.op_id in self._used:
            raise TargetRefused("credential already used")
        self._used.add(operation.op_id)
        result = self.apply(operation, call.args)
        entry = {"op_id": operation.op_id, "tool": operation.tool, "resource": operation.resource, "args": call.args}
        self.effects.append(entry)
        if self._log_path is not None:
            descriptor = os.open(self._log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, (json.dumps(entry, sort_keys=True) + "\n").encode())
            finally:
                os.close(descriptor)
        return result

    def apply(self, operation: Operation, args: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class RecordingTarget(SecuredTarget):
    """A fake target whose effect is to record that it happened."""

    def apply(self, operation: Operation, args: dict[str, Any]) -> dict[str, Any]:
        return {"applied": operation.tool, "resource": operation.resource}
