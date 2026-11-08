from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from agent_warrant.identity import generate_keypair

from executor.credentials import sign_effect_proof
from executor.protocol import args_digest
from executor.targets import EffectCall, Target, TargetRefused

from .agents import Agent
from .faults import CapturingTarget
from .story import Story
from .world import DEPLOY_SCOPE, PRINCIPAL, TENANT

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


SCENARIOS: list[tuple[int, str, Callable[[Story], None]]] = [
    (1, "happy path through one delegation hop", happy_path),
    (2, "budget exhaustion across hops", budget_exhaustion),
    (3, "root revocation cascades to every descendant", root_revocation_cascade),
    (4, "mid-chain revocation stops only that subtree", mid_chain_revocation),
    (5, "a stolen credential fails at the target", stolen_credential),
    (6, "a rogue issuer is refused by the trust policy", rogue_issuer),
]
