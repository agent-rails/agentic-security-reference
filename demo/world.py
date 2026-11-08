from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_warrant.identity import encode_public_key, generate_keypair
from agent_warrant.ledger import TaskLedger
from agent_warrant.task_root import issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from executor.client import send_request
from executor.config import Built, build_executor
from executor.credentials import write_executor_key
from executor.operator import Operator
from executor.protocol import Request
from executor.server import SOCKET_NAME, ExecutorServer

from .agents import Agent

EXECUTOR_ID = "executor.example"
ISSUER_ID = "issuer.example"
TENANT = "tenant-a"
PRINCIPAL = "user:alice"
BASE_TIME = 1_800_000_000
TOOLS = ("deploy.service", "deploy.rollback", "deploy.delete", "signer.withdraw")
DEPLOY_SCOPE = {"tools": ["deploy.*"], "resources": ["env/staging/*"], "max_cost_per_call": 5}
FULL_SCOPE = {
    "tools": ["deploy.*", "signer.withdraw"],
    "resources": ["env/staging/*", "wallet/*"],
    "max_cost_per_call": 100,
}


class FakeClock:
    def __init__(self, now: int = BASE_TIME) -> None:
        self.now = now

    def __call__(self) -> float:
        return float(self.now)

    def advance(self, seconds: int) -> None:
        self.now += seconds


def private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def write_private(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, content)
    finally:
        os.close(descriptor)


@dataclass
class Running:
    """A running executor. `built` is set when the executor runs inside this process; `process` when it runs as
    a separate process."""

    socket_path: Path
    server: ExecutorServer | None = None
    built: Built | None = None
    process: subprocess.Popen | None = None

    def stop(self) -> None:
        if self.server is not None:
            self.server.stop()
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=15)
            if self.process.stdout is not None:
                self.process.stdout.close()


@dataclass
class World:
    """Everything one scenario needs, in a fresh temporary directory: an issuer, an executor's state, secrets and
    configuration, and helpers that build agents and requests."""

    clock: Callable[[], float] = field(default_factory=FakeClock)
    root_dir: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="asr-")).resolve())
    issuer_key: Ed25519PrivateKey = field(default_factory=generate_keypair)
    secrets: dict[str, bytes] = field(default_factory=dict)
    running: Running | None = None
    agent_uid: int | None = None
    agent_gid: int | None = None

    def __post_init__(self) -> None:
        traverse = 0o700 if self.agent_uid is None else 0o711
        os.chmod(self.root_dir, traverse)
        self.exec_dir = private_dir(self.root_dir / "exec")
        os.chmod(self.exec_dir, traverse)
        self.config_path = self.exec_dir / "config.json"
        self.audit_path = self.exec_dir / "audit.jsonl"
        self.ledger_path = self.exec_dir / "ledger.db"
        self.audit_key = os.urandom(32)
        self.alert_key = os.urandom(32)
        self.executor_key = generate_keypair()
        self.secrets = {"deploy-api": os.urandom(32).hex().encode(), "signer": os.urandom(32).hex().encode()}
        self.effect_logs = {
            "deploy-api": self.exec_dir / "effects-deploy-api.jsonl",
            "signer": self.exec_dir / "effects-signer.jsonl",
        }
        self._write_state()

    @property
    def now(self) -> int:
        return int(self.clock())

    def _write_state(self) -> None:
        secrets_dir = private_dir(self.exec_dir / "secrets")
        for name, value in self.secrets.items():
            write_private(secrets_dir / name, value)
        write_executor_key(self.exec_dir / "executor.key", self.executor_key)
        write_private(self.exec_dir / "audit.key", self.audit_key)
        write_private(self.exec_dir / "alert.key", self.alert_key)
        if self.agent_uid is None:
            private_dir(self.exec_dir / "run")
        TaskLedger.create(self.ledger_path)
        self.config = self.make_config()
        write_private(self.config_path, json.dumps(self.config, indent=2).encode())

    def make_config(self) -> dict[str, Any]:
        return {
            "agent_uid": self.agent_uid,
            "agent_gid": self.agent_gid,
            "executor_id": EXECUTOR_ID,
            "run_dir": str(self.exec_dir / "run"),
            "state_dir": str(self.exec_dir / "state"),
            "ledger_path": str(self.ledger_path),
            "issuance_path": str(self.exec_dir / "issuance.jsonl"),
            "audit_path": str(self.audit_path),
            "audit_key_file": str(self.exec_dir / "audit.key"),
            "executor_key_file": str(self.exec_dir / "executor.key"),
            "secrets_dir": str(self.exec_dir / "secrets"),
            "releaser": "operator:oncall",
            "alert_key_file": str(self.exec_dir / "alert.key"),
            "alert_state_dir": str(self.exec_dir / "alert-state"),
            "alert_max_age": 300,
            "alert_policy": {
                "first_tool_use": "suspend",
                "first_resource_use": "revoke_task",
                "rate_above_baseline": "suspend",
                "outside_usual_hours": "report_only",
            },
            "max_credential_ttl": 30,
            "reservation_ttl": 60,
            "issuers": {
                ISSUER_ID: {
                    "public_key": encode_public_key(self.issuer_key.public_key()),
                    "max_budget": 1000,
                    "max_depth": 4,
                    "tenants": {TENANT: {"principals": [PRINCIPAL], "principal_prefixes": []}},
                }
            },
            "policy": {
                "default": "deny",
                "rules": [
                    {
                        "id": "no-delete",
                        "decision": "deny",
                        "tools": ["deploy.delete"],
                        "reason": "deletes are never automated",
                    },
                    {"id": "deploy", "decision": "allow", "tools": ["deploy.*"]},
                    {"id": "signer", "decision": "allow", "tools": ["signer.withdraw"]},
                ],
            },
            "costs": {
                "version": 1,
                "tools": {"deploy.service": 1, "deploy.rollback": 1, "deploy.delete": 1, "signer.withdraw": "amount"},
            },
            "targets": [
                {
                    "name": "deploy-api",
                    "audience": "deploy-api",
                    "secret": "deploy-api",
                    "tools": ["deploy.service", "deploy.rollback", "deploy.delete"],
                    "log_path": str(self.effect_logs["deploy-api"]),
                },
                {
                    "name": "signer",
                    "audience": "signer",
                    "secret": "signer",
                    "tools": ["signer.withdraw"],
                    "log_path": str(self.effect_logs["signer"]),
                },
            ],
        }

    def start_in_process(self, **overrides: Any) -> Running:
        built = build_executor(self.config, self.clock, **overrides)
        server = ExecutorServer(built.executor, built.run_dir, built.agent_uid, built.agent_gid)
        server.start_in_background()
        self.running = Running(server.socket_path, server=server, built=built)
        return self.running

    def start_process(self, env: Mapping[str, str] | None = None) -> Running:
        process = subprocess.Popen(
            [sys.executable, "-m", "executor", "--config", str(self.config_path)],
            stdout=subprocess.PIPE,
            text=True,
            env=dict(env if env is not None else {"PATH": os.environ.get("PATH", "")}),
            cwd=Path(__file__).resolve().parent.parent,
        )
        banner = process.stdout.readline()
        if "listening" not in banner:
            process.kill()
            raise RuntimeError(f"executor did not start: {banner!r}")
        self.running = Running(self.exec_dir / "run" / SOCKET_NAME, process=process)
        return self.running

    def operator(self) -> Operator:
        return Operator(self.config, self.clock)

    def stop(self) -> None:
        if self.running is not None:
            self.running.stop()
            self.running = None
        shutil.rmtree(self.root_dir, ignore_errors=True)

    def root_for(
        self,
        agent: Agent,
        *,
        task_id: str = "task-1",
        budget: int = 100,
        scope: dict[str, Any] | None = None,
        purpose: str = "release-bot",
        ttl: int = 3600,
        max_depth: int = 4,
        tenant: str = TENANT,
        principal: str = PRINCIPAL,
        issuer_key: Ed25519PrivateKey | None = None,
        issuer: str = ISSUER_ID,
    ) -> None:
        agent.root = issue_task_root(
            issuer_key or self.issuer_key,
            issuer=issuer,
            task_id=task_id,
            tenant_id=tenant,
            principal=principal,
            purpose=purpose,
            budget=budget,
            max_depth=max_depth,
            issued_at=self.now,
            expires_at=self.now + ttl,
            scope=scope or FULL_SCOPE,
            subject=agent.public_key,
        )
        agent.links = ()

    def send(self, agent: Agent, tool: str, resource: str, args: dict[str, Any], nonce: str, **extra: Any) -> dict:
        request = agent.request(
            audience=EXECUTOR_ID, now=self.now, tool=tool, resource=resource, args=args, nonce=nonce, **extra
        )
        return self.send_request(request)

    def send_request(self, request: Request) -> dict:
        return send_request(self.running.socket_path, request)

    def audit_rows(self) -> list[dict]:
        return [json.loads(line) for line in self.audit_path.read_text().splitlines() if line]

    def effects(self, target: str) -> list[dict]:
        path = self.effect_logs[target]
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
