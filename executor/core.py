from __future__ import annotations

import hashlib
import sys
import traceback
import uuid
from collections.abc import Callable, Mapping
from typing import Any

from agent_guard.audit import MemoryAuditSink
from agent_guard.decision import Decision, Verdict
from agent_guard.guard import Guard
from agent_guard.policy import Policy
from agent_warrant.chain import ChainRevocationChecker, verify_chain
from agent_warrant.ledger import LedgerUnavailable, Operation, Refused, TaskLedger
from agent_warrant.resolver import IssuerResolver
from agent_warrant.scope import covers
from agent_warrant.task_root import TaskRootResult
from agent_warrant.trust import IssuerTrustPolicy
from agentguard_identity.credentials import CredentialInjector, Refusal
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .costs import CostError, CostSchedule
from .credentials import sign_effect_proof
from .evidence import EvidenceWriter, Stamp, deny
from .protocol import ProtocolError, args_digest, decode_request, derive_op_id
from .targets import EffectCall, Target, TargetRefused


class Executor:
    """The only process that holds secrets and performs effects.

    For each request it: strict-decodes the frame; verifies the delegation chain against the trust policy, the
    ledger's revocations, this executor's audience and the request digest; checks the leaf scope and a
    policy-owned cost; asks the guard to decide; opens the task and reserves the cost in the ledger; has the
    injector mint a credential bound to the whole operation; performs the effect; and records evidence. The
    agent supplies the request and a leaf possession proof and nothing else: tenant, task, principal and cost
    never come from it."""

    def __init__(
        self,
        *,
        executor_id: str,
        resolver: IssuerResolver,
        trust_policy: IssuerTrustPolicy,
        ledger: TaskLedger,
        policy: Policy,
        costs: CostSchedule,
        injectors: Mapping[str, CredentialInjector],
        targets: Mapping[str, Target],
        executor_key: Ed25519PrivateKey,
        evidence: EvidenceWriter,
        clock: Callable[[], float],
        reservation_ttl: int,
    ) -> None:
        self._executor_id = executor_id
        self._resolver = resolver
        self._trust_policy = trust_policy
        self.ledger = ledger
        self._ledger = ledger
        self._revocations: ChainRevocationChecker = ledger
        self._policy = policy
        self._costs = costs
        self._injectors = dict(injectors)
        self._targets = dict(targets)
        self._executor_key = executor_key
        self._evidence = evidence
        self._clock = clock
        self._reservation_ttl = reservation_ttl

    def handle(self, frame: bytes) -> dict[str, Any]:
        try:
            return self._handle(frame)
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return _response("refused", "internal_error")

    def _handle(self, frame: bytes) -> dict[str, Any]:
        trace_id = uuid.uuid4().hex
        call_id = self._evidence.new_call_id()
        try:
            request = decode_request(frame)
        except ProtocolError as err:
            self._evidence.write(
                stamp=None,
                trace_id=trace_id,
                host=None,
                tool="unknown",
                resource="unknown",
                args={},
                verdict=deny(str(err), "malformed-request"),
                executed=False,
                event="decision",
                outcome="blocked",
                call_id=call_id,
                call_digest=None,
            )
            return _response("refused", "malformed_request", detail=str(err), trace_id=trace_id)
        trace_id = request.trace_id or trace_id
        now = int(self._clock())
        digest = request.digest()

        def refuse(reason: str, rule_id: str, stamp: Stamp | None, detail: str = "") -> dict[str, Any]:
            self._evidence.write(
                stamp=stamp,
                trace_id=trace_id,
                host=request.host,
                tool=request.tool,
                resource=request.resource,
                args=request.args,
                verdict=deny(detail or reason, rule_id),
                executed=False,
                event="decision",
                outcome="blocked",
                call_id=call_id,
                call_digest=None,
            )
            return _response("refused", reason, detail=detail, trace_id=trace_id)

        chain = verify_chain(
            request.task_root,
            list(request.links),
            request.leaf_proof,
            self._resolver,
            self._trust_policy,
            self._revocations,
            now,
            expected_audience=self._executor_id,
            expected_request_digest=digest,
        )
        if not chain.valid:
            return refuse("chain_invalid", "chain-invalid", None, chain.reason)
        stamp = Stamp.from_chain(chain)
        root = chain.root
        leaf = chain.links[-1] if chain.links else root
        if not covers(chain.leaf_scope, request.tool, request.resource):
            return refuse("out_of_scope", "scope", stamp)
        try:
            cost = self._costs.cost(request.tool, request.args)
        except CostError as err:
            return refuse("cost_unavailable", "cost-schedule", stamp, str(err))
        if cost > chain.leaf_scope["max_cost_per_call"]:
            return refuse("cost_over_call_cap", "scope-cost", stamp, f"cost {cost}")
        target = self._targets.get(request.tool)
        injector = self._injectors.get(request.tool)
        if target is None or injector is None:
            return refuse("no_target", "no-target", stamp)
        allowed, verdict = Guard(self._policy, MemoryAuditSink(), agent_id=stamp.actor).decide(
            request.tool, request.args
        )
        if not allowed:
            self._evidence.write(
                stamp=stamp,
                trace_id=trace_id,
                host=request.host,
                tool=request.tool,
                resource=request.resource,
                args=request.args,
                verdict=verdict if verdict.decision is Decision.DENY else deny(verdict.reason, verdict.rule_id or ""),
                executed=False,
                event="decision",
                outcome="blocked",
                call_id=call_id,
                call_digest=None,
            )
            return _response("refused", "policy_denied", detail=verdict.reason, trace_id=trace_id)
        if injector.suspended:
            return refuse("suspended", "suspended", stamp)

        try:
            self._ledger.open_task(TaskRootResult(valid=True, reason="ok", root=root, checked_at=now), now)
            operation = Operation(
                op_id=derive_op_id(root.tenant_id, root.task_id, leaf.binding(), digest),
                tenant_id=root.tenant_id,
                task_id=root.task_id,
                leaf_binding=leaf.binding(),
                tool=request.tool,
                resource=request.resource,
                args_digest=args_digest(request.args),
                cost=cost,
                verdict_allowed=True,
                expires_at=min(
                    now + self._reservation_ttl, root.expires_at, *(link.expires_at for link in chain.links)
                ),
            )
            reservation = self._ledger.reserve(operation, chain.links, now)
        except Refused as err:
            return refuse("reservation_refused", "ledger", stamp, str(err))
        except LedgerUnavailable as err:
            return refuse("ledger_unavailable", "ledger-unavailable", stamp, str(err))

        call_digest = hashlib.sha256(operation.digest().encode()).hexdigest()
        released = Verdict(Decision.ALLOW, verdict.reason, rule_id=verdict.rule_id)

        def record(event: str, outcome: str, executed: bool, error: str | None = None) -> None:
            self._evidence.write(
                stamp=stamp,
                trace_id=trace_id,
                host=request.host,
                tool=request.tool,
                resource=request.resource,
                args=request.args,
                verdict=released,
                executed=executed,
                event=event,
                outcome=outcome,
                call_id=call_id,
                call_digest=call_digest,
                error=error,
            )

        def finish(status: str, reason: str, outcome: str, error: str | None = None) -> dict[str, Any]:
            record("terminal", outcome, True, error)
            return _response(status, reason, op_id=operation.op_id, trace_id=trace_id, state=reservation.state)

        try:
            if reservation.state == "reserved":
                reservation = self._ledger.mark_issued(operation.tenant_id, operation.task_id, operation.op_id, now)
            elif reservation.state != "issued":
                return refuse(f"already_{reservation.state}", "replay", stamp)
        except (Refused, LedgerUnavailable) as err:
            return refuse("reservation_refused", "ledger", stamp, str(err))

        record("release", "pending", True)
        injected = injector.inject(operation, reservation)
        if isinstance(injected, Refusal):
            if injected.reason in ("already_issued", "mint_failed"):
                return self._unknown(operation, now, finish, injected.reason)
            record("terminal", "not_dispatched", False, injected.reason)
            return _response("refused", f"injector_{injected.reason}", op_id=operation.op_id, trace_id=trace_id)

        call = EffectCall(
            credential=injected.credential,
            proof=sign_effect_proof(self._executor_key, injected.credential),
            operation=operation.signable_fields(),
            args=request.args,
        )
        try:
            result = target.perform(call)
        except TargetRefused as err:
            return self._unknown(operation, now, finish, "target_refused", str(err))
        except Exception as err:
            return self._unknown(operation, now, finish, "target_error", f"{type(err).__name__}: {err}")
        try:
            reservation = self._ledger.mark_done(operation.tenant_id, operation.task_id, operation.op_id, now)
        except (Refused, LedgerUnavailable) as err:
            return finish("outcome_unknown", "effect_done_ledger_not_updated", "unknown", str(err))
        record("terminal", "returned", True)
        return _response("done", "ok", op_id=operation.op_id, trace_id=trace_id, state=reservation.state, result=result)

    def _unknown(self, operation: Operation, now: int, finish: Callable, reason: str, error: str | None = None) -> dict:
        try:
            self._ledger.mark_outcome_unknown(operation.tenant_id, operation.task_id, operation.op_id, now)
        except (Refused, LedgerUnavailable) as err:
            error = f"{error or reason}; ledger: {err}"
        return finish("outcome_unknown", reason, "unknown", error or reason)


def _response(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "status": status,
        "reason": reason,
        **{key: value for key, value in extra.items() if value not in (None, "")},
    }
