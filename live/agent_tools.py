"""The agent's side of a live run: a stdio MCP server that exposes deployment tools to a model and turns each call
into a signed request to the executor. It holds the agent's key and delegation chain and nothing else; it never
sees a secret or a credential."""

from __future__ import annotations

import base64
import json
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
            return {"document": self._read_document(str(arguments["name"]))}
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
        workspace = self._state.workspace.resolve()
        path = (workspace / name).resolve()
        if path.parent != workspace or not path.is_file():
            raise ToolError(f"no document named {name!r}")
        return path.read_text()

    def _log(self, entry: dict[str, Any]) -> None:
        with self._state.call_log.open("a") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


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
        try:
            result = tools.call(str(params.get("name")), dict(params.get("arguments") or {}))
            reply["result"] = {"content": [{"type": "text", "text": json.dumps(result)}], "isError": False}
        except (ToolError, KeyError, ValueError, OSError) as err:
            reply["result"] = {"content": [{"type": "text", "text": f"error: {err}"}], "isError": True}
    elif method == "ping":
        reply["result"] = {}
    else:
        reply["error"] = {"code": -32601, "message": f"method not found: {method}"}
    return reply


def serve(tools: AgentTools, reader: TextIO, writer: TextIO) -> None:
    for line in reader:
        if not line.strip():
            continue
        reply = handle_message(tools, json.loads(line))
        if reply is not None:
            writer.write(json.dumps(reply) + "\n")
            writer.flush()


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("usage: python -m live.agent_tools <agent-state.json>", file=sys.stderr)
        return 2
    serve(AgentTools(AgentState.load(Path(arguments[0]))), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
