from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agent_guard.audit import AuditSink, build_record
from agent_guard.decision import Decision, Verdict
from agent_warrant.chain import ChainLink
from agent_warrant.task_root import TaskRoot

UNVERIFIED = "unverified"


@dataclass(frozen=True)
class Stamp:
    """Evidence fields the executor takes from the verified chain. None of them is read from the request."""

    task_root: str
    grant_hash: str
    tenant_id: str
    principal: str
    actor: str
    parent_actor: str
    purpose: str

    @classmethod
    def from_chain(cls, root: TaskRoot, links: Sequence[ChainLink]) -> Stamp:
        """`actor` is the leaf holder's public key, `parent_actor` the key that delegated to it (the task root's
        issuer when the root's own subject acts), `principal` and `purpose` the signed task root's."""
        leaf = links[-1] if links else root
        return cls(
            task_root=root.binding(),
            grant_hash=leaf.binding(),
            tenant_id=root.tenant_id,
            principal=root.principal,
            actor=leaf.subject,
            parent_actor=leaf.issuer,
            purpose=root.purpose,
        )

    def fields(self) -> dict[str, str]:
        return {
            "task_root": self.task_root,
            "grant_hash": self.grant_hash,
            "tenant_id": self.tenant_id,
            "principal": self.principal,
            "actor": self.actor,
            "parent_actor": self.parent_actor,
            "purpose": self.purpose,
        }


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
        host: str | None,
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
                UNVERIFIED if stamp is None else stamp.actor,
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
                host=None if host is None else f"claim:{host}",
                **identity,
            )
        )


def deny(reason: str, rule_id: str) -> Verdict:
    return Verdict(Decision.DENY, reason, rule_id=rule_id)


def allow(reason: str, rule_id: str | None = None) -> Verdict:
    return Verdict(Decision.ALLOW, reason, rule_id=rule_id)
