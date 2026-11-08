import json
import os
import socket
import stat
import struct

import pytest
from agent_guard.audit import AuditRecord, verify_record
from agent_warrant.ledger import Refused

from demo.agents import Agent
from demo.world import DEPLOY_SCOPE, EXECUTOR_ID, World
from executor.client import send_frame
from executor.protocol import MAX_FRAME_BYTES, decode_request, derive_op_id, encode_request
from executor.server import ExecutorServer, prepare_run_dir

DEPLOY = ("deploy.service", "env/staging/api", {"image": "api:1"})


def test_happy_path_performs_the_effect_once_and_spends_the_cost(world, running, alice):
    response = world.send(alice, *DEPLOY, "n1")
    assert response["status"] == "done"
    assert response["state"] == "done"
    assert world.effects("deploy-api") == [
        {
            "op_id": response["op_id"],
            "tool": "deploy.service",
            "resource": "env/staging/api",
            "args": {"image": "api:1"},
        }
    ]
    status = running.built.ledger.task_budget("tenant-a", "task-1", world.now)
    assert (status.budget, status.spent) == (100, 1)


def test_evidence_records_are_signed_and_describe_the_lifecycle(world, running, alice):
    world.send(alice, *DEPLOY, "n1")
    rows = world.audit_rows()
    assert [(row["event"], row["outcome"]) for row in rows] == [("release", "pending"), ("terminal", "returned")]
    for row in rows:
        assert verify_record(AuditRecord(**row), world.audit_key)
        assert row["schema_version"] == 2
        assert row["task_root"] == alice.root.binding()
        assert row["grant_hash"] == alice.leaf.binding()
        assert row["tenant_id"] == "tenant-a"
        assert row["args"] == {"resource": "env/staging/api", "args": {"image": "api:1"}}


@pytest.mark.parametrize(
    "frame",
    [
        b"not json",
        b'{"tool": "deploy.service"}',
        b'{"task_root":"a","links":[],"leaf_proof":"b","tool":"deploy.service","resource":"r","args":{},"nonce":"n","tool":"x"}',
        b'{"task_root":"a","links":[],"leaf_proof":"b","tool":"deploy.service","resource":"r","args":{"x":1.5},"nonce":"n"}',
        b'{"task_root":"a","links":[],"leaf_proof":"b","tool":"deploy.*","resource":"r","args":{},"nonce":"n"}',
        b'{"task_root":"a","links":[],"leaf_proof":"b","tool":"deploy.service","resource":"*","args":{},"nonce":"n"}',
        b'{"task_root":"a","links":[],"leaf_proof":"b","tool":"deploy.service","resource":"r","args":[],"nonce":"n"}',
    ],
)
def test_malformed_requests_are_refused_and_nothing_runs(world, running, frame):
    response = send_frame(running.socket_path, frame)
    assert response["status"] == "refused"
    assert response["reason"] == "malformed_request"
    assert world.effects("deploy-api") == []


def test_wire_request_has_no_op_id_field(world, running, alice):
    request = alice.request(
        audience=EXECUTOR_ID, now=world.now, tool=DEPLOY[0], resource=DEPLOY[1], args=DEPLOY[2], nonce="n1"
    )
    body = json.loads(encode_request(request))
    body["op_id"] = "chosen-by-agent"
    response = send_frame(running.socket_path, json.dumps(body).encode())
    assert response["reason"] == "malformed_request"
    assert world.effects("deploy-api") == []


def test_oversized_frame_is_dropped_without_reading_it(world, running):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(running.socket_path))
        connection.sendall(struct.pack(">I", MAX_FRAME_BYTES + 1))
        assert connection.recv(1) == b""


def test_proof_for_another_request_is_refused(world, running, alice):
    request = alice.request(
        audience=EXECUTOR_ID, now=world.now, tool=DEPLOY[0], resource=DEPLOY[1], args=DEPLOY[2], nonce="n1"
    )
    tampered = json.loads(encode_request(request))
    tampered["args"] = {"image": "evil:1"}
    response = send_frame(running.socket_path, json.dumps(tampered).encode())
    assert response["reason"] == "chain_invalid"
    assert "request digest" in response["detail"]
    assert world.effects("deploy-api") == []


def test_proof_addressed_to_another_verifier_is_refused(world, running, alice):
    request = alice.request(
        audience="other-executor", now=world.now, tool=DEPLOY[0], resource=DEPLOY[1], args=DEPLOY[2], nonce="n1"
    )
    response = world.send_request(request)
    assert response["reason"] == "chain_invalid"
    assert "audience" in response["detail"]


def test_tool_outside_scope_is_refused(world, running):
    agent = Agent("narrow")
    world.root_for(agent, scope=DEPLOY_SCOPE)
    response = world.send(agent, "signer.withdraw", "wallet/hot-1", {"amount": 1}, "n1")
    assert response["reason"] == "out_of_scope"
    assert world.effects("signer") == []


def test_resource_outside_scope_is_refused(world, running):
    agent = Agent("narrow")
    world.root_for(agent, scope=DEPLOY_SCOPE)
    response = world.send(agent, "deploy.service", "env/prod/api", {}, "n1")
    assert response["reason"] == "out_of_scope"


def test_cost_above_the_per_call_cap_is_refused(world, running):
    agent = Agent("capped")
    world.root_for(agent, scope={"tools": ["signer.withdraw"], "resources": ["wallet/*"], "max_cost_per_call": 10})
    response = world.send(agent, "signer.withdraw", "wallet/hot-1", {"amount": 11}, "n1")
    assert response["reason"] == "cost_over_call_cap"
    assert world.effects("signer") == []


def test_agent_cannot_state_its_own_cost(world, running):
    agent = Agent("capped")
    world.root_for(agent, scope={"tools": ["signer.withdraw"], "resources": ["wallet/*"], "max_cost_per_call": 100})
    assert world.send(agent, "signer.withdraw", "wallet/hot-1", {"amount": 7, "cost": 0}, "n1")["status"] == "done"
    assert running.built.ledger.task_budget("tenant-a", "task-1", world.now).spent == 7


def test_guard_policy_can_deny_a_tool_the_scope_allows(world, running, alice):
    response = world.send(alice, "deploy.delete", "env/staging/api", {}, "n1")
    assert response["reason"] == "policy_denied"
    assert world.effects("deploy-api") == []
    assert world.audit_rows()[-1]["rule_id"] == "no-delete"


def test_identical_request_is_not_performed_twice(world, running, alice):
    first = world.send(alice, *DEPLOY, "n1")
    second = world.send(alice, *DEPLOY, "n1")
    assert first["status"] == "done"
    assert second["status"] == "refused"
    assert second["reason"] == "already_done"
    assert len(world.effects("deploy-api")) == 1
    assert running.built.ledger.task_budget("tenant-a", "task-1", world.now).spent == 1


def test_new_nonce_is_a_new_operation(world, running, alice):
    assert world.send(alice, *DEPLOY, "n1")["status"] == "done"
    assert world.send(alice, *DEPLOY, "n2")["status"] == "done"
    assert len(world.effects("deploy-api")) == 2


def test_op_id_is_derived_from_tenant_task_leaf_and_request():
    base = ("t1", "a", "leaf", "d")
    assert derive_op_id(*base) == derive_op_id(*base)
    for position, other in enumerate(("t2", "b", "leaf2", "e")):
        changed = list(base)
        changed[position] = other
        assert derive_op_id(*changed) != derive_op_id(*base)
    assert derive_op_id("t1", "a|b", "l", "d") != derive_op_id("t1", "a", "b|l", "d")


def test_two_holders_sending_the_same_request_are_two_operations(world, running, alice):
    from demo.world import DEPLOY_SCOPE

    bob = Agent("bob")
    alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=5, ttl=600, now=world.now)
    assert world.send(alice, *DEPLOY, "n1")["status"] == "done"
    assert world.send(bob, *DEPLOY, "n1")["status"] == "done"
    assert len(world.effects("deploy-api")) == 2


def test_socket_is_private_and_run_dir_is_checked(world, running, tmp_path):
    assert stat.S_IMODE(os.stat(running.socket_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(running.socket_path.parent).st_mode) == 0o700
    loose = tmp_path / "loose"
    loose.mkdir(mode=0o755)
    os.chmod(loose, 0o755)
    with pytest.raises(ValueError, match="0700"):
        prepare_run_dir(loose)


def test_second_server_on_the_same_socket_is_refused(world, running):
    with pytest.raises(ValueError, match="already exists"):
        ExecutorServer(running.built.executor, running.built.run_dir)


def test_request_round_trips_through_the_strict_decoder(world, alice):
    request = alice.request(
        audience=EXECUTOR_ID,
        now=world.now,
        tool=DEPLOY[0],
        resource=DEPLOY[1],
        args=DEPLOY[2],
        nonce="n1",
        host="laptop-7",
    )
    assert decode_request(encode_request(request)) == request


def test_unlisted_issuer_is_refused(world, running):
    from agent_warrant.identity import generate_keypair

    agent = Agent("rogue")
    world.root_for(agent, issuer_key=generate_keypair(), issuer="rogue.example")
    assert world.send(agent, *DEPLOY, "n1")["reason"] == "chain_invalid"
    assert world.effects("deploy-api") == []


def test_suspended_executor_refuses_before_reserving(world, running, alice):
    running.built.suspend("test", actor="operator:oncall")
    response = world.send(alice, *DEPLOY, "n1")
    assert response["reason"] == "suspended"
    with pytest.raises(Refused, match="unknown task"):
        running.built.ledger.task_budget("tenant-a", "task-1", world.now)
    assert world.effects("deploy-api") == []


def test_world_is_isolated_per_test(world, running):
    assert isinstance(world, World)
