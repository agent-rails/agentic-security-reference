from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_guard.alert_sink import AlertOutcome, AlertSink, sign_alert
from agent_guard.detect import DetectConfig, detect_file
from agent_guard.keyfile import load_key_file
from agent_warrant.ledger import TaskLedger
from agentguard_identity.credentials import CredentialInjector, JsonlIssuanceStore

from .credentials import EmptySecretStore

WRITER_ID = "detector"
ALERT_KEY_MIN_BYTES = 32


class _NoMinter:
    def mint(self, *_: Any) -> Any:
        raise RuntimeError("the operator holds no secrets and mints nothing")


class LedgerRevocationWriter:
    """Alert sink's revocation seam: an alert names a task root binding, and the ledger revokes that binding.
    Every chain below the root fails its next verification."""

    def __init__(self, ledger: TaskLedger, clock: Callable[[], float]) -> None:
        self._ledger = ledger
        self._clock = clock

    def revoke_task(self, task_root: str, reason: str, actor: str) -> None:
        self._ledger.revoke(task_root, int(self._clock()))


class Operator:
    """The trusted side that stops things. It shares the executor's ledger file and suspension directory and
    holds no secret: its injector has an empty secret store. Kill levers: `suspend` is the effect stop (new
    credentials are refused), `revoke_*` is the authority stop (chains stop verifying). `route_alerts` runs the
    detector over the signed audit log and applies the configured response to each alert."""

    def __init__(self, config: Mapping[str, Any], clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self.ledger = TaskLedger.open(config["ledger_path"])
        self._injector = CredentialInjector(
            store=EmptySecretStore(),
            minter=_NoMinter(),
            issuance=JsonlIssuanceStore(config["issuance_path"]),
            secret_names={},
            executor_key_id="operator",
            audience="operator",
            max_ttl=1,
            clock=clock,
            state_dir=Path(config["state_dir"]),
            releaser=config["releaser"],
        )
        self._audit_path = Path(config["audit_path"])
        self._audit_key = load_key_file(config["audit_key_file"], "audit key", ALERT_KEY_MIN_BYTES)
        self._alert_key = load_key_file(config["alert_key_file"], "alert key", ALERT_KEY_MIN_BYTES)
        self._sink = AlertSink(
            self._alert_key,
            WRITER_ID,
            self._injector,
            config["alert_policy"],
            LedgerRevocationWriter(self.ledger, clock),
            state_dir=Path(config["alert_state_dir"]),
            clock=clock,
            max_age=config["alert_max_age"],
        )

    @property
    def suspended(self) -> bool:
        return self._injector.suspended

    def suspend(self, reason: str, actor: str) -> None:
        self._injector.suspend(reason, actor)

    def resume(self, releaser: str) -> None:
        self._injector.resume(releaser)

    def revoke_binding(self, binding: str) -> None:
        self.ledger.revoke(binding, int(self._clock()))

    def revoke_task(self, tenant_id: str, task_id: str) -> None:
        self.ledger.revoke_task(tenant_id, task_id, int(self._clock()))

    def revoke_tenant(self, tenant_id: str) -> None:
        self.ledger.revoke_tenant(tenant_id, int(self._clock()))

    def route_alerts(self, evaluate_from: datetime, **detect_options: Any) -> list[AlertOutcome]:
        """Detect persona deviations after `evaluate_from` (earlier rows are the baseline) and apply the
        configured response to each alert. Returns one outcome per alert."""
        result = detect_file(
            self._audit_path, DetectConfig(evaluate_from=evaluate_from, **detect_options), secret=self._audit_key
        )
        return [
            self._sink.handle(sign_alert(alert, self._alert_key, WRITER_ID, int(self._clock())))
            for alert in result.alerts
        ]
