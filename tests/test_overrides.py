from demo.agents import Agent
from demo.faults import CapturingTarget, CrashingMinter
from demo.world import World
from executor.credentials import HmacMinter


def test_target_and_ledger_wrappers_sit_on_the_real_objects():
    seen = {"targets": [], "ledgers": []}

    def wrap_target(target):
        seen["targets"].append(target)
        return CapturingTarget(target)

    def wrap_ledger(ledger):
        seen["ledgers"].append(ledger)
        return ledger

    world = World()
    try:
        world.start_in_process(target_wrapper=wrap_target, ledger_wrapper=wrap_ledger)
        agent = Agent("a")
        world.root_for(agent)
        assert world.send(agent, "deploy.service", "env/staging/api", {}, "n1")["status"] == "done"
        assert len(seen["targets"]) == 2
        assert len(seen["ledgers"]) == 1
        assert len(world.effects("deploy-api")) == 1
    finally:
        world.stop()


def test_crashing_minter_fails_the_first_attempts_then_mints():
    minter = CrashingMinter(HmacMinter(lambda: 1.0), crashes=1)
    try:
        minter.mint(b"s", "kid", "aud", "rd", 5.0)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected a simulated crash")
    assert minter.mint(b"s", "kid", "aud", "rd", 5.0)["aud"] == "aud"
    assert minter.attempts == 2
