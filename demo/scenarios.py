from __future__ import annotations

from collections.abc import Callable

from .agents import Agent
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


SCENARIOS: list[tuple[int, str, Callable[[Story], None]]] = [
    (1, "happy path through one delegation hop", happy_path),
    (2, "budget exhaustion across hops", budget_exhaustion),
]
