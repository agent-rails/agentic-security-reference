from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from agent_guard.audit import AuditSink, build_record
from agent_guard.decision import Decision, Verdict
from agent_warrant.chain import ChainVerifyResult

UNVERIFIED = "unverified"


@dataclass(frozen=True)
class Stamp:
    """Evidence fields the executor takes from the verified chain. None of them is read from the request."""

    task_root: str
    grant_hash: str
    tenant_id: str

    @classmethod
    def from_chain(cls, chain: ChainVerifyResult) -> Stamp:
        leaf = chain.links[-1] if chain.links else chain.root
        return cls(task_root=chain.root.binding(), grant_hash=leaf.binding(), tenant_id=chain.root.tenant_id)

    def fields(self) -> dict[str, str]:
        return {"task_root": self.task_root, "grant_hash": self.grant_hash, "tenant_id": self.tenant_id}


class EvidenceWriter:
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def new_call_id(self) -> str:
        return uuid.uuid4().hex

    def write(
        self,
        *,
        stamp: Stamp | None,
        trace_id: str,
        tool: str,
        resource: str,
        args: dict[str, Any],
        verdict: Verdict,
        executed: bool,
        event: str,
        outcome: str,
        call_id: str,
        call_digest: str | None,
        error: str | None = None,
    ) -> None:
        identity = stamp.fields() if stamp is not None else {}
        self._sink.write(
            build_record(
                UNVERIFIED if stamp is None else stamp.grant_hash,
                tool,
                {"resource": resource, "args": args},
                verdict,
                executed,
                error,
                event=event,
                call_id=call_id,
                call_digest=call_digest,
                outcome=outcome,
                trace_id=trace_id,
                **identity,
            )
        )


def deny(reason: str, rule_id: str) -> Verdict:
    return Verdict(Decision.DENY, reason, rule_id=rule_id)


def allow(reason: str, rule_id: str | None = None) -> Verdict:
    return Verdict(Decision.ALLOW, reason, rule_id=rule_id)
