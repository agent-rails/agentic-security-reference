import os
from datetime import UTC, datetime

import pytest

from demo.agents import Agent
from executor.operator import AuditIntegrityError, Operator

DEPLOY = ("deploy.service", "env/staging/api", {"image": "api:1"})


def test_revoking_the_root_binding_stops_the_chain(world, running, alice):
    assert world.send(alice, *DEPLOY, "n1")["status"] == "done"
    world.operator().revoke_binding(alice.root.binding())
    response = world.send(alice, *DEPLOY, "n2")
    assert response["reason"] == "chain_invalid"
    assert "revoked" in response["detail"]


def test_revoking_a_task_or_a_tenant_stops_the_chain(world, running):
    first, second = Agent("a"), Agent("b")
    world.root_for(first, task_id="task-1")
    world.root_for(second, task_id="task-2")
    operator = world.operator()
    operator.revoke_task("tenant-a", "task-1")
    assert world.send(first, *DEPLOY, "n1")["reason"] == "chain_invalid"
    assert world.send(second, *DEPLOY, "n1")["status"] == "done"
    operator.revoke_tenant("tenant-a")
    assert world.send(second, *DEPLOY, "n2")["reason"] == "chain_invalid"


def test_suspend_refuses_new_credentials_and_only_the_releaser_resumes(world, running, alice):
    operator = world.operator()
    operator.suspend("incident", actor="operator:oncall")
    assert world.send(alice, *DEPLOY, "n1")["reason"] == "suspended"
    with pytest.raises(PermissionError):
        operator.resume("someone-else")
    assert world.send(alice, *DEPLOY, "n2")["reason"] == "suspended"
    operator.resume("operator:oncall")
    assert world.send(alice, *DEPLOY, "n3")["status"] == "done"


def test_operator_needs_no_secret_directory(world, running):
    for entry in (world.exec_dir / "secrets").iterdir():
        entry.unlink()
    (world.exec_dir / "secrets").rmdir()
    assert Operator(world.config, world.clock).suspended is False


def test_alert_for_a_new_tool_suspends_the_executor(world, running, alice):
    for nonce in ("b1", "b2", "b3"):
        assert world.send(alice, *DEPLOY, nonce)["status"] == "done"
    boundary = datetime.now(UTC)
    assert world.send(alice, "deploy.rollback", "env/staging/api", {}, "x1")["status"] == "done"
    outcomes = world.operator().route_alerts(boundary)
    assert [(outcome.action, outcome.applied) for outcome in outcomes] == [("suspend", True)]
    assert world.send(alice, *DEPLOY, "n9")["reason"] == "suspended"


def test_alert_for_a_new_resource_revokes_the_live_chain_mid_task(world, running, alice):
    for nonce in ("b1", "b2", "b3"):
        assert world.send(alice, *DEPLOY, nonce)["status"] == "done"
    boundary = datetime.now(UTC)
    assert world.send(alice, "deploy.service", "env/staging/web", {}, "x1")["status"] == "done"
    outcomes = world.operator().route_alerts(boundary)
    assert [(outcome.action, outcome.applied, outcome.reason) for outcome in outcomes] == [
        ("revoke_task", True, "revoked")
    ]
    response = world.send(alice, *DEPLOY, "n9")
    assert response["reason"] == "chain_invalid"
    assert "revoked" in response["detail"]
    assert len(world.effects("deploy-api")) == 4


def test_tampered_audit_rows_are_not_trusted_by_the_detector(world, running, alice):
    for nonce in ("b1", "b2"):
        world.send(alice, *DEPLOY, nonce)
    boundary = datetime.now(UTC)
    world.send(alice, *DEPLOY, "x1")
    forged = world.audit_path.read_text().replace('"tool": "deploy.service"', '"tool": "deploy.rollback"')
    lines = forged.splitlines()
    world.audit_path.write_text(
        "\n".join(lines[:-2] + [line.replace("deploy.service", "deploy.rollback") for line in lines[-2:]]) + "\n"
    )
    assert "deploy.rollback" in world.audit_path.read_text()
    operator = world.operator()
    with pytest.raises(AuditIntegrityError, match="unverified"):
        operator.route_alerts(boundary)
    assert operator.suspended is False


def deviate(world, alice):
    for nonce in ("b1", "b2", "b3"):
        assert world.send(alice, *DEPLOY, nonce)["status"] == "done"
    boundary = datetime.now(UTC)
    assert world.send(alice, "deploy.rollback", "env/staging/api", {}, "x1")["status"] == "done"
    return boundary


def test_rescanning_the_same_log_after_resume_does_not_suspend_again(world, running, alice):
    boundary = deviate(world, alice)
    operator = world.operator()
    assert [outcome.applied for outcome in operator.route_alerts(boundary)] == [True]
    operator.resume("operator:oncall")
    assert operator.route_alerts(boundary) == []
    assert world.operator().route_alerts(boundary) == []
    assert operator.suspended is False


def test_rescanning_after_the_replay_window_does_not_act_again(world, running, alice):
    boundary = deviate(world, alice)
    operator = world.operator()
    operator.route_alerts(boundary)
    operator.resume("operator:oncall")
    world.clock.advance(world.config["alert_max_age"] + 60)
    assert world.operator().route_alerts(boundary) == []
    assert operator.suspended is False


def test_a_new_deviation_after_a_rescan_still_acts(world, running, alice):
    boundary = deviate(world, alice)
    operator = world.operator()
    operator.route_alerts(boundary)
    operator.resume("operator:oncall")
    assert world.send(alice, "deploy.service", "env/staging/web", {}, "x2")["status"] == "done"
    assert [outcome.action for outcome in operator.route_alerts(boundary)] == ["revoke_task"]


def test_operator_refuses_an_alert_state_dir_others_can_reach(world):
    state = world.exec_dir / "alert-state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o770)
    with pytest.raises(ValueError, match="alert_state_dir"):
        world.operator()
