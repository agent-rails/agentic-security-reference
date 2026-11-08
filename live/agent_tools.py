"""The agent's side of a live run: a stdio MCP server that exposes deployment tools to a model and turns each call
into a signed request to the executor. It holds the agent's key and delegation chain and nothing else; it never
sees a secret or a credential."""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from agent_warrant.chain import ChainLink, prove_leaf
from agent_warrant.task_root import TaskRoot
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from executor.client import send_request
from executor.protocol import Request, encode_request, request_digest

PROTOCOL_VERSION = "2025-06-18"
MAX_LINE_CHARACTERS = 1_048_576
MAX_DOCUMENT_BYTES = 65_536
SERVER_INFO = {"name": "agent-tools", "version": "0.1.0"}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "deploy_service",
        "description": "Deploy a container image to a service environment, for example env/staging/api.",
        "inputSchema": {
            "type": "object",
            "properties": {"resource": {"type": "string"}, "image": {"type": "string"}},
            "required": ["resource", "image"],
        },
    },
    {
        "name": "rollback_service",
        "description": "Roll a service environment back to its previous release.",
        "inputSchema": {
            "type": "object",
            "properties": {"resource": {"type": "string"}},
            "required": ["resource"],
        },
    },
    {
        "name": "withdraw_funds",
        "description": "Withdraw an amount from a wallet, for example wallet/hot-1.",
        "inputSchema": {
            "type": "object",
            "properties": {"wallet": {"type": "string"}, "amount": {"type": "integer"}},
            "required": ["wallet", "amount"],
        },
    },
    {
        "name": "read_document",
        "description": "Read a document from the shared workspace by name.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
]


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class AgentState:
    """What the agent process is given: its own key, its delegation chain, where the executor listens, where the
    untrusted workspace documents are, and where to log its calls."""

    key: Ed25519PrivateKey
    root: TaskRoot
    links: tuple[ChainLink, ...]
    audience: str
    socket_path: Path
    workspace: Path
    call_log: Path
    env_log: Path | None = None

    @property
    def leaf(self) -> TaskRoot | ChainLink:
        return self.links[-1] if self.links else self.root

    @classmethod
    def load(cls, path: Path) -> AgentState:
        data = json.loads(path.read_text())
        return cls(
            key=Ed25519PrivateKey.from_private_bytes(base64.b64decode(data["key"])),
            root=TaskRoot.decode(data["task_root"]),
            links=tuple(ChainLink.decode(link) for link in data["links"]),
            audience=data["audience"],
            socket_path=Path(data["socket_path"]),
            workspace=Path(data["workspace"]),
            call_log=Path(data["call_log"]),
            env_log=Path(data["env_log"]) if data.get("env_log") else None,
        )


def effect_for(name: str, arguments: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """Maps a tool call to the executor's tool, resource and arguments."""
    if name == "deploy_service":
        return "deploy.service", str(arguments["resource"]), {"image": str(arguments["image"])}
    if name == "rollback_service":
        return "deploy.rollback", str(arguments["resource"]), {}
    if name == "withdraw_funds":
        amount = arguments["amount"]
        if type(amount) is not int:
            raise ToolError("amount must be an integer")
        return "signer.withdraw", str(arguments["wallet"]), {"amount": amount}
    raise ToolError(f"unknown tool {name!r}")


class AgentTools:
    def __init__(self, state: AgentState, clock: Callable[[], float] = time.time) -> None:
        self._state = state
        self._clock = clock

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "read_document":
            document = self._read_document(str(arguments["name"]))
            self._log({"ts": self._clock(), "tool": "read_document", "resource": str(arguments["name"])})
            return {"document": document}
        tool, resource, args = effect_for(name, arguments)
        request = self._request(tool, resource, args)
        started = time.monotonic()
        response = send_request(self._state.socket_path, request)
        latency_ms = round((time.monotonic() - started) * 1000, 2)
        self._log(
            {
                "ts": self._clock(),
                "tool": tool,
                "resource": resource,
                "args": args,
                "frame": encode_request(request).decode(),
                "status": response.get("status"),
                "reason": response.get("reason"),
                "latency_ms": latency_ms,
            }
        )
        return response

    def _request(self, tool: str, resource: str, args: dict[str, Any]) -> Request:
        nonce = uuid.uuid4().hex
        now = int(self._clock())
        proof = prove_leaf(
            self._state.leaf,
            self._state.key,
            now,
            audience=self._state.audience,
            request_digest=request_digest(tool, resource, args, nonce),
        )
        return Request(
            task_root=self._state.root.encode(),
            links=tuple(link.encode() for link in self._state.links),
            leaf_proof=proof.encode(),
            tool=tool,
            resource=resource,
            args=args,
            nonce=nonce,
        )

    def _read_document(self, name: str) -> str:
        """Reads one regular file directly inside the workspace: no path separators, no symlinks, size capped."""
        if not name or "/" in name or "\0" in name or name in (".", ".."):
            raise ToolError(f"no document named {name!r}")
        directory = os.open(self._state.workspace, os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except OSError:
                raise ToolError(f"no document named {name!r}") from None
        finally:
            os.close(directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ToolError(f"no document named {name!r}")
            if info.st_size > MAX_DOCUMENT_BYTES:
                raise ToolError(f"document {name!r} is over {MAX_DOCUMENT_BYTES} bytes")
            return os.read(descriptor, MAX_DOCUMENT_BYTES + 1).decode()
        finally:
            os.close(descriptor)

    def _log(self, entry: dict[str, Any]) -> None:
        with self._state.call_log.open("a") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def error(message_id: Any, code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": text}}


def reply_to(tools: AgentTools, line: str) -> dict[str, Any] | None:
    """One line of JSON-RPC in, at most one reply out. Malformed input gets an error reply, never a crash."""
    if len(line) > MAX_LINE_CHARACTERS:
        return error(None, -32600, "message is too long")
    try:
        message = json.loads(line)
    except ValueError:
        return error(None, -32700, "parse error")
    if not isinstance(message, dict):
        return error(None, -32600, "message must be an object")
    if "params" in message and not isinstance(message["params"], dict):
        return error(message.get("id"), -32602, "params must be an object") if "id" in message else None
    try:
        return handle_message(tools, message)
    except Exception as err:
        return error(message.get("id"), -32603, f"internal error: {type(err).__name__}")


def handle_message(tools: AgentTools, message: dict[str, Any]) -> dict[str, Any] | None:
    """One JSON-RPC message in, at most one out. Notifications get no reply."""
    method = message.get("method")
    if "id" not in message:
        return None
    reply: dict[str, Any] = {"jsonrpc": "2.0", "id": message["id"]}
    if method == "initialize":
        requested = message.get("params", {}).get("protocolVersion", PROTOCOL_VERSION)
        reply["result"] = {
            "protocolVersion": requested,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    elif method == "tools/list":
        reply["result"] = {"tools": TOOLS}
    elif method == "tools/call":
        params = message.get("params", {})
        arguments = params.get("arguments") or {}
        try:
            if not isinstance(arguments, dict):
                raise ToolError("arguments must be an object")
            result = tools.call(str(params.get("name")), arguments)
            reply["result"] = {"content": [{"type": "text", "text": json.dumps(result)}], "isError": False}
        except (ToolError, KeyError, ValueError, OSError) as err:
            reply["result"] = {"content": [{"type": "text", "text": f"error: {err}"}], "isError": True}
    elif method == "ping":
        reply["result"] = {}
    else:
        reply["error"] = {"code": -32601, "message": f"method not found: {method}"}
    return reply


def read_line(reader: TextIO) -> str | None:
    """The next line, or an over-long marker without holding more than the limit in memory; None at end of input."""
    line = reader.readline(MAX_LINE_CHARACTERS + 1)
    if not line:
        return None
    if len(line) > MAX_LINE_CHARACTERS and not line.endswith("\n"):
        while True:
            rest = reader.readline(MAX_LINE_CHARACTERS)
            if not rest or rest.endswith("\n"):
                break
    return line


def serve(tools: AgentTools, reader: TextIO, writer: TextIO) -> None:
    while (line := read_line(reader)) is not None:
        if not line.strip():
            continue
        reply = reply_to(tools, line)
        if reply is not None:
            writer.write(json.dumps(reply) + "\n")
            writer.flush()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: python -m live.agent_tools <agent-state.json>", file=sys.stderr)
        return 2
    state = AgentState.load(Path(arguments[0]))
    if state.env_log is not None:
        state.env_log.write_text(json.dumps(sorted(os.environ)))
    serve(AgentTools(state), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
