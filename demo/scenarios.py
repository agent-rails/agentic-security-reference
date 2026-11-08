from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from agent_warrant.identity import generate_keypair
from agent_warrant.ledger import TaskLedger

from executor.credentials import HmacMinter, sign_effect_proof
from executor.protocol import args_digest, encode_request
from executor.targets import EffectCall, Target, TargetRefused

from .agents import Agent
from .faults import CapturingTarget, CrashingMinter, FlakyLedger
from .story import Story
from .world import DEPLOY_SCOPE, EXECUTOR_ID, PRINCIPAL, TENANT, World

REPO = Path(__file__).resolve().parent.parent

DEPLOY = ("deploy.service", "env/staging/api", {"image": "api:1"})


def happy_path(story: Story) -> None:
    """A human's task root is delegated one hop; the second agent's call reaches the target through the executor."""
    with story.world() as world:
        running = world.start_in_process()
        alice = story.name(Agent("alice"), "release-bot")
        bob = story.name(Agent("bob"), "deploy-helper")
        world.root_for(alice, budget=20, purpose="release-bot")
        story.say(f"{PRINCIPAL} authorised a task root for release-bot: budget 20, tenant {TENANT}")
        alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=5, ttl=600, now=world.now)
        story.say("release-bot delegated a narrower scope and budget 5 to deploy-helper")
        response = world.send(bob, *DEPLOY, "n1")
        story.outcome("deploy-helper deploys through the executor", response, "done")
        story.expect("the deploy API performed the effect once", len(world.effects("deploy-api")), 1)
        story.expect("budget spent on the task", running.built.ledger.task_budget(TENANT, "task-1", world.now).spent, 1)
        rows = world.audit_rows()
        story.expect("evidence principal", rows[-1]["principal"], PRINCIPAL)
        story.expect("evidence actor", story.who(rows[-1]["actor"]), "deploy-helper")
        story.expect("evidence parent actor", story.who(rows[-1]["parent_actor"]), "release-bot")
        story.expect("evidence purpose", rows[-1]["purpose"], "release-bot")


def budget_exhaustion(story: Story) -> None:
    """A link's budget caps its holder; every call also spends the shared task pool."""
    with story.world() as world:
        running = world.start_in_process()
        alice = story.name(Agent("alice"), "release-bot")
        bob = story.name(Agent("bob"), "deploy-helper")
        world.root_for(alice, budget=5)
        alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=3, ttl=600, now=world.now)
        story.say("task budget 5; deploy-helper's link carries budget 3; each deploy costs 1")
        for number in range(1, 4):
            story.outcome(f"deploy-helper call {number}", world.send(bob, *DEPLOY, f"b{number}"), "done")
        response = world.send(bob, *DEPLOY, "b4")
        story.outcome("deploy-helper call 4 hits its link cap", response, "refused", "reservation_refused")
        story.expect("refusal names the link budget", "link budget exhausted" in response["detail"], True)
        for number in range(1, 3):
            story.outcome(
                f"release-bot call {number} spends the rest of the pool",
                world.send(alice, *DEPLOY, f"a{number}"),
                "done",
            )
        response = world.send(alice, *DEPLOY, "a3")
        story.outcome("release-bot call 3 hits the task pool", response, "refused", "reservation_refused")
        story.expect("refusal names the task budget", "task budget exhausted" in response["detail"], True)
        story.expect("effects performed", len(world.effects("deploy-api")), 5)
        story.expect("pool spent", running.built.ledger.task_budget(TENANT, "task-1", world.now).spent, 5)


def root_revocation_cascade(story: Story) -> None:
    """Revoking the task root stops every holder below it, including delegations made earlier."""
    with story.world() as world:
        world.start_in_process()
        operator = world.operator()
        alice = story.name(Agent("alice"), "release-bot")
        bob = story.name(Agent("bob"), "deploy-helper")
        carol = story.name(Agent("carol"), "sub-helper")
        other = story.name(Agent("other"), "other-task")
        world.root_for(alice, task_id="task-1")
        world.root_for(other, task_id="task-2")
        alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=10, ttl=600, now=world.now)
        bob.delegate_to(carol, scope=DEPLOY_SCOPE, budget=5, ttl=600, now=world.now)
        for agent in (alice, bob, carol):
            story.outcome(
                f"{story.who(agent.public_key)} before revocation", world.send(agent, *DEPLOY, "before"), "done"
            )
        operator.revoke_binding(alice.root.binding())
        story.say("operator revoked the task root binding in the ledger")
        for agent in (alice, bob, carol):
            response = world.send(agent, *DEPLOY, "after")
            story.outcome(f"{story.who(agent.public_key)} after revocation", response, "refused", "chain_invalid")
            story.expect("reason", "revoked" in response["detail"], True)
        story.outcome("an unrelated task is unaffected", world.send(other, *DEPLOY, "n1"), "done")
        story.expect("effects performed", len(world.effects("deploy-api")), 4)


def mid_chain_revocation(story: Story) -> None:
    """Revoking one link stops that holder and everything delegated from it, and nobody else."""
    with story.world() as world:
        world.start_in_process()
        operator = world.operator()
        alice = story.name(Agent("alice"), "release-bot")
        bob = story.name(Agent("bob"), "deploy-helper")
        carol = story.name(Agent("carol"), "other-helper")
        dave = story.name(Agent("dave"), "bobs-sub-helper")
        world.root_for(alice)
        alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=10, ttl=600, now=world.now)
        alice.delegate_to(carol, scope=DEPLOY_SCOPE, budget=10, ttl=600, now=world.now)
        bob.delegate_to(dave, scope=DEPLOY_SCOPE, budget=5, ttl=600, now=world.now)
        operator.revoke_binding(bob.links[0].binding())
        story.say("operator revoked the link that gave deploy-helper its authority")
        for agent in (bob, dave):
            response = world.send(agent, *DEPLOY, "n1")
            story.outcome(f"{story.who(agent.public_key)} is stopped", response, "refused", "chain_invalid")
        for agent in (alice, carol):
            story.outcome(f"{story.who(agent.public_key)} keeps working", world.send(agent, *DEPLOY, "n1"), "done")
        story.expect("effects performed", len(world.effects("deploy-api")), 2)


def stolen_credential(story: Story) -> None:
    """The Binance pattern: a credential is copied and presented elsewhere. The target refuses it."""
    captured: list[CapturingTarget] = []

    def capture(target: Target) -> Target:
        wrapped = CapturingTarget(target)
        captured.append(wrapped)
        return wrapped

    with story.world() as world:
        world.start_in_process(target_wrapper=capture)
        signer = next(target for target in captured if "signer.withdraw" in target.tools)
        trader = story.name(Agent("trader"), "treasury-bot")
        world.root_for(
            trader, scope={"tools": ["signer.withdraw"], "resources": ["wallet/*"], "max_cost_per_call": 100}
        )
        response = world.send(trader, "signer.withdraw", "wallet/hot-1", {"amount": 10}, "w1")
        story.outcome("legitimate withdrawal of 10", response, "done")
        call = signer.calls[0]
        story.say("an attacker now holds the credential and the call that carried it")
        attacker_key = generate_keypair()

        def attempt(label: str, offered: EffectCall, reason: str) -> None:
            try:
                signer.inner.perform(offered)
            except TargetRefused as err:
                story.expect(label, str(err), reason)
            else:
                story.expect(label, "accepted", reason)

        forged = replace(call, proof=sign_effect_proof(attacker_key, call.credential))
        attempt("credential signed with the attacker's own key", forged, "holder proof invalid")
        greedy_args = {"amount": 1000}
        attempt(
            "captured call with larger arguments",
            replace(call, args=greedy_args),
            "arguments differ from the operation",
        )
        greedy_operation = {**call.operation, "cost": 1000, "args_digest": args_digest(greedy_args)}
        attempt(
            "captured call with a rewritten operation",
            replace(call, operation=greedy_operation, args=greedy_args),
            "credential was issued for a different operation",
        )
        attempt("captured call replayed unchanged", call, "credential already used")
        world.clock.advance(31)
        attempt("captured call after the credential expired", call, "credential expired")
        story.expect("withdrawals performed", [e["args"] for e in world.effects("signer")], [{"amount": 10}])


def rogue_issuer(story: Story) -> None:
    """A validly signed task root is not enough: the executor's trust policy must list the issuer and its claims."""
    with story.world() as world:
        world.start_in_process()
        rogue_key = generate_keypair()
        cases = [
            ("unlisted issuer", {"issuer_key": rogue_key, "issuer": "rogue.example"}, "not in the trust policy"),
            ("listed issuer name, wrong key", {"issuer_key": rogue_key}, "invalid issuer signature"),
            ("tenant the issuer may not assert", {"tenant": "tenant-b"}, "may not assert tenant"),
            ("principal the issuer may not assert", {"principal": "user:mallory"}, "may not assert principal"),
            ("budget above the issuer's allowance", {"budget": 5000}, "exceeds issuer allowance"),
        ]
        for label, options, reason in cases:
            agent = Agent("rogue")
            world.root_for(agent, **options)
            response = world.send(agent, *DEPLOY, "n1")
            story.outcome(label, response, "refused", "chain_invalid")
            story.expect(f"{label}: reason", reason in response["detail"], True)
        story.expect("effects performed", len(world.effects("deploy-api")), 0)


def kill_levers(story: Story) -> None:
    """Two independent stops: the effect stop refuses new credentials, the authority stop revokes chains."""
    with story.world() as world:
        world.start_in_process()
        operator = world.operator()
        first, second = Agent("first"), Agent("second")
        world.root_for(first, task_id="task-1")
        world.root_for(second, task_id="task-2")
        story.outcome("before any stop", world.send(first, *DEPLOY, "n1"), "done")
        operator.suspend("incident 42", actor="operator:oncall")
        story.say("effect stop: operator suspended credential injection")
        for agent in (first, second):
            story.outcome("a request while suspended", world.send(agent, *DEPLOY, "n2"), "refused", "suspended")
        try:
            operator.resume("agent-or-anyone-else")
        except PermissionError:
            story.say("resume by anyone but the named releaser raised PermissionError")
        else:
            story.expect("resume by anyone but the named releaser", "accepted", "refused")
        story.outcome("still suspended", world.send(first, *DEPLOY, "n3"), "refused", "suspended")
        operator.resume("operator:oncall")
        story.outcome("after the named releaser resumed", world.send(first, *DEPLOY, "n4"), "done")
        operator.revoke_tenant("tenant-a")
        story.say("authority stop: operator revoked the tenant in the ledger")
        for agent in (first, second):
            story.outcome(
                "a request after tenant revocation", world.send(agent, *DEPLOY, "n5"), "refused", "chain_invalid"
            )
        story.expect("effects performed", len(world.effects("deploy-api")), 2)
        story.say("limit: a credential already issued stays valid until its ttl (30 s here); the stops act on new ones")


def crash_recovery(story: Story) -> None:
    """A fault between steps never issues two credentials and never loses track of what may have happened. Each
    injected fault is followed by a restart: the executor is stopped and a new one is built from the state on
    disk. The faults are raised inside the process; a killed process is not simulated."""
    with story.world() as world:
        flaky: list[FlakyLedger] = []

        def wrap(ledger: TaskLedger) -> FlakyLedger:
            flaky.append(FlakyLedger(ledger, "mark_issued"))
            return flaky[0]

        running = world.start_in_process(ledger_wrapper=wrap)
        agent = Agent("agent")
        world.root_for(agent)
        response = world.send(agent, *DEPLOY, "n1")
        story.outcome("crash after the reservation, before issuing", response, "refused", "reservation_refused")
        story.expect(
            "no effect and no credential yet", (len(world.effects("deploy-api")), issuance_count(world)), (0, 0)
        )
        running.stop()
        running = world.start_in_process()
        response = world.send(agent, *DEPLOY, "n1")
        story.outcome("after a restart, the agent retries the same request", response, "done")
        story.expect(
            "one effect, one credential, cost charged once",
            (len(world.effects("deploy-api")), issuance_count(world)),
            (1, 1),
        )
        story.expect("spent", running.built.ledger.task_budget(TENANT, "task-1", world.now).spent, 1)
    with story.world() as world:
        minter = CrashingMinter(HmacMinter(world.clock), crashes=1)
        running = world.start_in_process(minter=minter)
        agent = Agent("agent")
        world.root_for(agent)
        response = world.send(agent, *DEPLOY, "n1")
        story.outcome("crash while minting, after the issuance record", response, "outcome_unknown", "mint_failed")
        running.stop()
        running = world.start_in_process()
        story.outcome(
            "after a restart, the agent retries the same request",
            world.send(agent, *DEPLOY, "n1"),
            "refused",
            "already_outcome_unknown",
        )
        story.expect("one issuance record on disk, no second credential", issuance_count(world), 1)
        story.expect("no effect was performed", len(world.effects("deploy-api")), 0)
        reservation = running.built.ledger.reservation(TENANT, "task-1", response["op_id"], world.now)
        story.expect("ledger surfaces the operation for an operator", reservation.state, "outcome_unknown")
        story.expect(
            "its cost stays spent, never credited back",
            running.built.ledger.task_budget(TENANT, "task-1", world.now).spent,
            1,
        )
        terminal = [row for row in world.audit_rows() if row["event"] == "terminal"]
        story.expect("evidence records the unknown outcome", terminal[-1]["outcome"], "unknown")


def issuance_count(world: World) -> int:
    path = world.exec_dir / "issuance.jsonl"
    return len(path.read_text().splitlines()) if path.exists() else 0


def persona_deviation(story: Story) -> None:
    """In-scope but unusual: the call is allowed, a deterministic check over the evidence flags it, the
    executor is suspended."""
    with story.world() as world:
        world.start_in_process()
        operator = world.operator()
        agent = story.name(Agent("agent"), "release-bot")
        world.root_for(agent, purpose="release-bot")
        for number in range(1, 4):
            story.outcome(f"baseline deploy {number}", world.send(agent, *DEPLOY, f"b{number}"), "done")
        boundary = datetime.now(UTC)
        response = world.send(agent, "deploy.rollback", "env/staging/api", {}, "x1")
        story.outcome("in scope, policy allows, never used by this persona before", response, "done")
        started = time.perf_counter()
        outcomes = operator.route_alerts(boundary)
        story.expect("alert response", [(o.action, o.applied) for o in outcomes], [("suspend", True)])
        story.say(f"signal to suspension: {(time.perf_counter() - started) * 1000:.0f} ms (detector run over the log)")
        story.outcome("next request", world.send(agent, *DEPLOY, "n9"), "refused", "suspended")
        story.expect("detection is after the fact: the flagged call was performed", len(world.effects("deploy-api")), 4)


def alert_stops_live_chain(story: Story) -> None:
    """An alert revokes the task root in the ledger; a live delegation chain stops mid-task."""
    with story.world() as world:
        running = world.start_in_process()
        operator = world.operator()
        alice = story.name(Agent("alice"), "release-bot")
        bob = story.name(Agent("bob"), "deploy-helper")
        world.root_for(alice, purpose="release-bot", budget=50)
        alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=20, ttl=600, now=world.now)
        for number in range(1, 4):
            story.outcome(f"baseline deploy {number}", world.send(bob, *DEPLOY, f"b{number}"), "done")
        boundary = datetime.now(UTC)
        story.outcome(
            "first use of resource env/staging/web",
            world.send(bob, "deploy.service", "env/staging/web", {}, "x1"),
            "done",
        )
        outcomes = operator.route_alerts(boundary)
        story.expect(
            "alert response", [(o.action, o.applied, o.reason) for o in outcomes], [("revoke_task", True, "revoked")]
        )
        for agent in (bob, alice):
            response = world.send(agent, *DEPLOY, "after")
            story.outcome(f"{story.who(agent.public_key)} after the alert", response, "refused", "chain_invalid")
        status = running.built.ledger.task_budget(TENANT, "task-1", world.now)
        story.expect("budget left unspent on the revoked task", status.budget - status.spent, 46)


def enforced_mode(story: Story) -> None:
    """The executor runs as its own process and holds every secret; the agent process holds none."""
    with story.world(real_time=True) as world:
        running = world.start_process()
        agent = Agent("agent")
        world.root_for(agent)
        frames = [
            encode_request(
                agent.request(
                    audience=EXECUTOR_ID, now=world.now, tool=DEPLOY[0], resource=DEPLOY[1], args=DEPLOY[2], nonce="n1"
                )
            ).decode()
        ]
        environment = {"PATH": os.environ["PATH"]}
        argv = [sys.executable, "-m", "demo.agent_process", str(running.socket_path)]
        result = subprocess.run(
            argv, input=json.dumps(frames), capture_output=True, text=True, env=environment, cwd=REPO, timeout=60
        )
        story.expect("agent process exit code", result.returncode, 0)
        report = json.loads(result.stdout)
        story.expect("the agent process got its effect", report["responses"][0]["status"], "done")
        secrets = [value.decode() for value in world.secrets.values()]
        story.expect(
            "no secret in the agent's argv or environment",
            any(s in " ".join(report["argv"]) + " ".join(report["env"].values()) for s in secrets),
            False,
        )
        story.expect(
            "no secret or credential in what the executor returned",
            any(s in result.stdout for s in secrets) or "mac" in result.stdout,
            False,
        )
        story.expect("socket mode", oct(stat.S_IMODE(running.socket_path.stat().st_mode)), "0o600")
        story.expect("socket directory mode", oct(stat.S_IMODE(running.socket_path.parent.stat().st_mode)), "0o700")
        story.expect("ledger mode", oct(stat.S_IMODE(world.ledger_path.stat().st_mode)), "0o600")
        story.say(
            "limits: this run uses one OS user, which can still read these files; set agent_uid and agent_gid to run "
            "the agent as another user (tests/test_separate_user.py); egress is not restricted (no egress proxy)"
        )


SCENARIOS: list[tuple[int, str, Callable[[Story], None]]] = [
    (1, "happy path through one delegation hop", happy_path),
    (2, "budget exhaustion across hops", budget_exhaustion),
    (3, "root revocation cascades to every descendant", root_revocation_cascade),
    (4, "mid-chain revocation stops only that subtree", mid_chain_revocation),
    (5, "a stolen credential fails at the target", stolen_credential),
    (6, "a rogue issuer is refused by the trust policy", rogue_issuer),
    (7, "kill levers: effect stop and authority stop", kill_levers),
    (8, "crash recovery without double issue", crash_recovery),
    (9, "enforced mode: executor in its own process", enforced_mode),
    (10, "in-scope action outside the persona is flagged and suspended", persona_deviation),
    (11, "an alert stops a live delegation chain", alert_stops_live_chain),
]
