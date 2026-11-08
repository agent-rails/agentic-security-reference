from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any

from agent_warrant.canonical import canonicalize, strict_decode
from agent_warrant.encoding import sha256_b64u
from agent_warrant.scope import validate_entry

MAX_FRAME_BYTES = 1_048_576
HEADER = struct.Struct(">I")
REQUEST_DOMAIN = b"agentic-security-reference/request/v1\x00"
OP_ID_DOMAIN = b"agentic-security-reference/op-id/v1\x00"
MAX_NONCE_CHARACTERS = 64
MAX_LINKS = 16

REQUIRED_FIELDS = ("task_root", "links", "leaf_proof", "tool", "resource", "args", "nonce")
OPTIONAL_FIELDS = ("trace_id", "host")


class ProtocolError(Exception):
    pass


@dataclass(frozen=True)
class Request:
    task_root: str
    links: tuple[str, ...]
    leaf_proof: str
    tool: str
    resource: str
    args: dict[str, Any]
    nonce: str
    trace_id: str | None = None
    host: str | None = None

    def digest(self) -> str:
        return request_digest(self.tool, self.resource, self.args, self.nonce)


def request_digest(tool: str, resource: str, args: dict[str, Any], nonce: str) -> str:
    """What the agent's leaf proof binds: the exact tool, resource, arguments and nonce, and nothing the
    executor chooses, so an agent can compute it before sending."""
    body = canonicalize({"tool": tool, "resource": resource, "args": args, "nonce": nonce})
    return sha256_b64u(REQUEST_DOMAIN + body)


def derive_op_id(tenant_id: str, task_id: str, digest_of_request: str) -> str:
    """Idempotency key for one request. Always derived by the executor from the verified tenant and task and the
    request digest; the wire request has no op_id field, so an agent cannot choose or collide one."""
    body = canonicalize({"tenant_id": tenant_id, "task_id": task_id, "request": digest_of_request})
    return sha256_b64u(OP_ID_DOMAIN + body)


def args_digest(args: dict[str, Any]) -> str:
    return sha256_b64u(canonicalize(args))


def _concrete_id(label: str, value: Any) -> str:
    problem = validate_entry(value)
    if problem or "*" in value:
        raise ProtocolError(f"{label} must be a concrete id: {problem or 'no wildcards'}")
    return value


def decode_request(frame: bytes) -> Request:
    try:
        fields = strict_decode(
            frame, required=REQUIRED_FIELDS, optional=OPTIONAL_FIELDS, max_bytes=MAX_FRAME_BYTES, max_depth=8
        )
    except ValueError as err:
        raise ProtocolError(f"malformed request: {err}") from None
    for name in ("task_root", "leaf_proof"):
        if not isinstance(fields[name], str):
            raise ProtocolError(f"{name} must be a string")
    links = fields["links"]
    if not isinstance(links, list) or len(links) > MAX_LINKS or not all(isinstance(item, str) for item in links):
        raise ProtocolError(f"links must be a list of at most {MAX_LINKS} strings")
    tool = _concrete_id("tool", fields["tool"])
    resource = _concrete_id("resource", fields["resource"])
    if not isinstance(fields["args"], dict):
        raise ProtocolError("args must be an object")
    nonce = fields["nonce"]
    if not isinstance(nonce, str) or not nonce or len(nonce) > MAX_NONCE_CHARACTERS:
        raise ProtocolError("nonce must be a non-empty string")
    if not all("!" <= character <= "~" for character in nonce):
        raise ProtocolError("nonce must be ASCII printable without whitespace")
    trace_id = fields.get("trace_id")
    if trace_id is not None and (
        not isinstance(trace_id, str)
        or len(trace_id) != 32
        or trace_id.strip("0123456789abcdef")
        or trace_id == "0" * 32
    ):
        raise ProtocolError("trace_id must be 32 lowercase hex characters, not all zero")
    host = fields.get("host")
    if host is not None and (
        not isinstance(host, str) or not 0 < len(host) <= 128 or not all("!" <= c <= "~" for c in host)
    ):
        raise ProtocolError("host must be a short ASCII printable string")
    return Request(
        task_root=fields["task_root"],
        links=tuple(links),
        leaf_proof=fields["leaf_proof"],
        tool=tool,
        resource=resource,
        args=fields["args"],
        nonce=nonce,
        trace_id=trace_id,
        host=host,
    )


def encode_request(request: Request) -> bytes:
    body: dict[str, Any] = {
        "task_root": request.task_root,
        "links": list(request.links),
        "leaf_proof": request.leaf_proof,
        "tool": request.tool,
        "resource": request.resource,
        "args": request.args,
        "nonce": request.nonce,
    }
    if request.trace_id is not None:
        body["trace_id"] = request.trace_id
    if request.host is not None:
        body["host"] = request.host
    return canonicalize(body)


def read_frame(connection: socket.socket) -> bytes:
    header = _read_exactly(connection, HEADER.size)
    (length,) = HEADER.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise ProtocolError(f"frame of {length} bytes is over the {MAX_FRAME_BYTES} byte limit")
    return _read_exactly(connection, length)


def write_frame(connection: socket.socket, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("frame is over the size limit")
    connection.sendall(HEADER.pack(len(payload)) + payload)


def _read_exactly(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
