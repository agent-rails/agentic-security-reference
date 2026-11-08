from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_guard.audit import JsonlAuditSink, SigningAuditSink
from agent_guard.decision import Decision
from agent_guard.keyfile import load_key_file
from agent_guard.policy import Policy, Rule
from agent_warrant.identity import decode_public_key
from agent_warrant.ledger import TaskLedger
from agent_warrant.resolver import PinnedResolver
from agent_warrant.trust import IssuerAllowance, IssuerTrustPolicy, TenantAllowance
from agentguard_identity.credentials import CredentialInjector, JsonlIssuanceStore

from .core import Executor
from .costs import CostSchedule
from .credentials import FileSecretStore, HmacMinter, executor_key_id, load_executor_key
from .evidence import EvidenceWriter
from .targets import RecordingTarget, Target

AUDIT_KEY_MIN_BYTES = 32


@dataclass(frozen=True)
class Built:
    executor: Executor
    ledger: TaskLedger
    injectors: dict[str, CredentialInjector]
    run_dir: Path
    agent_uid: int | None = None
    agent_gid: int | None = None

    def suspend(self, reason: str, actor: str) -> None:
        next(iter(self.injectors.values())).suspend(reason, actor)

    def resume(self, releaser: str) -> None:
        next(iter(self.injectors.values())).resume(releaser)

    @property
    def suspended(self) -> bool:
        return any(injector.suspended for injector in self.injectors.values())


def load_config(path: Path) -> dict[str, Any]:
    """The configuration decides who is trusted, so it must be a regular file owned by this user that no other
    user can write."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError(f"config must be a regular file owned by this user and not writable by others: {path}")
        config: dict[str, Any] = json.loads(handle.read())
    return config


def build_trust_policy(issuers: Mapping[str, Any]) -> tuple[PinnedResolver, IssuerTrustPolicy]:
    keys = {name: decode_public_key(entry["public_key"]) for name, entry in issuers.items()}
    allowances = {
        name: IssuerAllowance(
            tenants={
                tenant: TenantAllowance(
                    principals=allowance.get("principals", []),
                    principal_prefixes=allowance.get("principal_prefixes", []),
                )
                for tenant, allowance in entry["tenants"].items()
            },
            max_budget=entry["max_budget"],
            max_depth=entry["max_depth"],
        )
        for name, entry in issuers.items()
    }
    return PinnedResolver(keys), IssuerTrustPolicy(allowances)


def build_policy(policy: Mapping[str, Any]) -> Policy:
    rules = [
        Rule(
            id=rule["id"],
            decision=Decision(rule["decision"]),
            tools=tuple(rule["tools"]),
            arg_patterns=tuple(rule.get("arg_patterns", [])),
            reason=rule.get("reason", ""),
        )
        for rule in policy["rules"]
    ]
    return Policy(default=Decision(policy["default"]), rules=rules)


def build_executor(
    config: Mapping[str, Any],
    clock: Callable[[], float] = time.time,
    *,
    minter: Any = None,
    targets: Mapping[str, Target] | None = None,
) -> Built:
    """Wire an Executor from a configuration. `minter` and `targets` replace the defaults (an HMAC minter and
    recording fake targets built from the config) so a test can inject a fault or inspect a target."""
    secrets = FileSecretStore(Path(config["secrets_dir"]))
    key = load_executor_key(Path(config["executor_key_file"]))
    key_id = executor_key_id(key)
    resolver, trust_policy = build_trust_policy(config["issuers"])
    costs = CostSchedule(version=config["costs"]["version"], tools=dict(config["costs"]["tools"]))
    secret_names: dict[str, str] = {}
    audiences: dict[str, str] = {}
    built_targets: dict[str, Target] = {}
    for entry in config["targets"]:
        log_path = Path(entry["log_path"]) if "log_path" in entry else None
        target = RecordingTarget(
            entry["name"], entry["audience"], secrets.get(entry["secret"]), key_id, entry["tools"], clock, log_path
        )
        for tool in entry["tools"]:
            secret_names[tool] = entry["secret"]
            audiences[tool] = entry["audience"]
            built_targets[tool] = target
    unserved = set(costs.tools) - set(secret_names)
    if unserved:
        raise ValueError(f"cost schedule prices tools no target serves: {sorted(unserved)}")
    issuance = JsonlIssuanceStore(config["issuance_path"])
    injectors = {
        tool: CredentialInjector(
            store=secrets,
            minter=minter or HmacMinter(clock),
            issuance=issuance,
            secret_names={tool: secret_names[tool]},
            executor_key_id=key_id,
            audience=audiences[tool],
            max_ttl=config["max_credential_ttl"],
            clock=clock,
            state_dir=Path(config["state_dir"]),
            releaser=config["releaser"],
        )
        for tool in secret_names
    }
    audit_path = Path(config["audit_path"])
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    os.close(os.open(audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))
    audit_key = load_key_file(config["audit_key_file"], "audit key", AUDIT_KEY_MIN_BYTES)
    executor = Executor(
        executor_id=config["executor_id"],
        resolver=resolver,
        trust_policy=trust_policy,
        ledger=TaskLedger.open(config["ledger_path"]),
        policy=build_policy(config["policy"]),
        costs=costs,
        injectors=injectors,
        targets=targets if targets is not None else built_targets,
        executor_key=key,
        evidence=EvidenceWriter(SigningAuditSink(JsonlAuditSink(audit_path), audit_key)),
        clock=clock,
        reservation_ttl=config["reservation_ttl"],
    )
    agent_uid = config.get("agent_uid")
    agent_gid = config.get("agent_gid")
    for name, value in (("agent_uid", agent_uid), ("agent_gid", agent_gid)):
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{name} must be a non-negative integer id")
    return Built(
        executor=executor,
        ledger=executor.ledger,
        injectors=injectors,
        run_dir=Path(config["run_dir"]),
        agent_uid=agent_uid,
        agent_gid=agent_gid,
    )
