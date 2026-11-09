import json
import os
import socket
import stat
import struct
import threading
import time

import pytest
from agent_guard.audit import AuditRecord, verify_record
from agent_warrant.ledger import Refused

from demo.agents import Agent
from demo.world import DEPLOY_SCOPE, EXECUTOR_ID, World
from executor import server as server_module
from executor.client import send_frame
from executor.config import load_config
from executor.credentials import executor_key_id
from executor.protocol import MAX_FRAME_BYTES, ProtocolError, decode_request, derive_op_id, encode_request
from executor.server import ExecutorServer, prepare_run_dir
from executor.targets import RecordingTarget

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


def test_identical_request_in_a_later_second_returns_the_stored_state(world, running, alice):
    assert world.send(alice, *DEPLOY, "n1")["status"] == "done"
    world.clock.advance(2)
    retry = world.send(alice, *DEPLOY, "n1")
    assert retry["status"] == "refused"
    assert retry["reason"] == "already_done"
    assert len(world.effects("deploy-api")) == 1
    assert running.built.ledger.task_budget("tenant-a", "task-1", world.now).spent == 1


def test_retry_after_an_unknown_outcome_reports_it_and_never_runs_again(world, running, alice):
    target = running.built.executor._targets["deploy.service"]
    perform = target.perform

    def perform_then_lose_the_response(call):
        perform(call)
        raise TimeoutError("response lost after the effect")

    target.perform = perform_then_lose_the_response
    first = world.send(alice, *DEPLOY, "n1")
    target.perform = perform
    world.clock.advance(2)
    retry = world.send(alice, *DEPLOY, "n1")
    assert first["status"] == "outcome_unknown"
    assert retry["status"] == "refused"
    assert retry["reason"] == "already_outcome_unknown"
    assert len(world.effects("deploy-api")) == 1
    assert running.built.ledger.task_budget("tenant-a", "task-1", world.now).spent == 1


def test_retry_after_a_crash_between_marking_issued_and_minting_runs_once(world, running, alice):
    ledger = running.built.ledger
    mark_issued = ledger.mark_issued

    def mark_issued_then_crash(*args, **kwargs):
        mark_issued(*args, **kwargs)
        raise RuntimeError("crash after mark_issued, before minting")

    ledger.mark_issued = mark_issued_then_crash
    first = world.send(alice, *DEPLOY, "n1")
    ledger.mark_issued = mark_issued
    world.clock.advance(2)
    retry = world.send(alice, *DEPLOY, "n1")
    again = world.send(alice, *DEPLOY, "n1")
    assert first["status"] == "refused"
    assert retry["status"] == "done"
    assert again["reason"] == "already_done"
    assert len(world.effects("deploy-api")) == 1
    assert len((world.exec_dir / "issuance.jsonl").read_text().splitlines()) == 1
    assert ledger.task_budget("tenant-a", "task-1", world.now).spent == 1


def test_retry_after_the_reservation_expired_unissued_is_refused_as_released(world, running, alice):
    ledger = running.built.ledger
    mark_issued = ledger.mark_issued

    def crash_before_marking_issued(*args, **kwargs):
        raise RuntimeError("crash before mark_issued")

    ledger.mark_issued = crash_before_marking_issued
    world.send(alice, *DEPLOY, "n1")
    ledger.mark_issued = mark_issued
    world.clock.advance(running.built.executor._reservation_ttl + 1)
    retry = world.send(alice, *DEPLOY, "n1")
    assert retry["status"] == "refused"
    assert retry["reason"] == "already_released"
    assert world.effects("deploy-api") == []
    assert ledger.task_budget("tenant-a", "task-1", world.now).spent == 0


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


class _BlockingTarget(RecordingTarget):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.entered = threading.Event()
        self.release = threading.Event()

    def apply(self, operation, args):
        self.entered.set()
        assert self.release.wait(10)
        return super().apply(operation, args)


class _FailingMinter:
    def mint(self, *args, **kwargs):
        raise RuntimeError("mint failed")


def test_replay_while_the_first_request_is_in_flight_leaves_the_first_one_alone(world, alice):
    target = _BlockingTarget(
        "deploy-api",
        "deploy-api",
        world.secrets["deploy-api"],
        executor_key_id(world.executor_key),
        ["deploy.service", "deploy.rollback", "deploy.delete"],
        world.clock,
    )
    running = world.start_in_process(targets={"deploy.service": target})
    first: dict = {}
    sender = threading.Thread(target=lambda: first.update(world.send(alice, *DEPLOY, "n1")))
    sender.start()
    assert target.entered.wait(10)
    replay = world.send(alice, *DEPLOY, "n1")
    target.release.set()
    sender.join(10)
    assert (replay["status"], replay["reason"]) == ("refused", "in_progress")
    assert (first["status"], first["state"]) == ("done", "done")
    assert running.built.ledger.reservation("tenant-a", "task-1", first["op_id"], world.now).state == "done"
    assert len(target.effects) == 1


def test_unknown_outcome_reports_the_state_after_the_transition(world, alice):
    world.start_in_process(minter=_FailingMinter())
    response = world.send(alice, *DEPLOY, "n1")
    assert (response["status"], response["reason"]) == ("outcome_unknown", "mint_failed")
    assert response["state"] == "outcome_unknown"


def test_evidence_marks_executed_only_once_the_target_was_called(world, alice):
    world.start_in_process(minter=_FailingMinter())
    world.send(alice, *DEPLOY, "n1")
    assert [(row["event"], row["executed"]) for row in world.audit_rows()] == [
        ("release", False),
        ("terminal", False),
    ]


def test_evidence_of_a_performed_effect_is_marked_executed_at_the_terminal_row(world, running, alice):
    world.send(alice, *DEPLOY, "n1")
    assert [(row["event"], row["executed"]) for row in world.audit_rows()] == [
        ("release", False),
        ("terminal", True),
    ]


def test_frame_must_arrive_before_an_absolute_deadline(world, monkeypatch):
    monkeypatch.setattr(server_module, "FRAME_DEADLINE_SECONDS", 0.5, raising=False)
    running = world.start_in_process()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(running.socket_path))
        connection.sendall(struct.pack(">I", 100))
        started = time.monotonic()
        closed = False
        while time.monotonic() - started < 5:
            try:
                connection.sendall(b"x")
            except OSError:
                closed = True
                break
            time.sleep(0.1)
        assert closed
        assert time.monotonic() - started < 3


def test_connections_over_the_cap_are_closed_and_service_recovers(world, alice, monkeypatch):
    monkeypatch.setattr(server_module, "MAX_CONNECTIONS", 2, raising=False)
    running = world.start_in_process()
    idle = []
    for _ in range(2):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(10)
        connection.connect(str(running.socket_path))
        connection.sendall(b"\x00")
        idle.append(connection)
    time.sleep(0.2)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as extra:
        extra.settimeout(10)
        extra.connect(str(running.socket_path))
        assert extra.recv(1) == b""
    for connection in idle:
        connection.close()
    time.sleep(0.2)
    assert world.send(alice, *DEPLOY, "n1")["status"] == "done"


def test_run_dir_under_a_parent_others_can_write_is_refused(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    with pytest.raises(ValueError, match="writable"):
        prepare_run_dir(shared / "run")


def test_run_dir_under_a_sticky_shared_parent_is_accepted(tmp_path):
    shared = tmp_path / "sticky"
    shared.mkdir()
    os.chmod(shared, 0o1777)
    assert prepare_run_dir(shared / "run") == shared / "run"


def test_peer_other_than_the_allowed_user_is_closed_without_a_response(world, alice, monkeypatch):
    monkeypatch.setattr(server_module, "peer_uid", lambda connection: os.geteuid() + 1, raising=False)
    running = world.start_in_process()
    with pytest.raises((ProtocolError, OSError)):
        send_frame(running.socket_path, b"{}")
    assert world.effects("deploy-api") == []


def test_separate_user_mode_opens_the_socket_to_the_agent_group_only():
    world = World(agent_uid=os.geteuid() + 1, agent_gid=os.getegid())
    try:
        running = world.start_in_process()
        for path, mode in ((running.socket_path.parent, 0o710), (running.socket_path, 0o660)):
            info = os.stat(path)
            assert (stat.S_IMODE(info.st_mode), info.st_gid) == (mode, os.getegid())
        for path in (world.exec_dir / "secrets").iterdir():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        agent = Agent("alice")
        world.root_for(agent)
        request = agent.request(
            audience=EXECUTOR_ID, now=world.now, tool=DEPLOY[0], resource=DEPLOY[1], args=DEPLOY[2], nonce="n1"
        )
        with pytest.raises((ProtocolError, OSError)):
            send_frame(running.socket_path, encode_request(request))
        assert world.effects("deploy-api") == []
    finally:
        world.stop()


@pytest.mark.parametrize(
    ("agent_uid", "agent_gid", "match"),
    [
        (os.geteuid(), os.getegid(), "agent_uid"),
        (0, os.getegid(), "agent_uid"),
        (os.geteuid() + 1, None, "agent_gid"),
        (os.geteuid() + 1, 0, "agent_gid"),
        (os.geteuid() + 1, max(os.getgroups() + [os.getegid()]) + 12345, "agent_gid"),
    ],
)
def test_separate_user_mode_refuses_an_unsafe_agent_user_or_group(agent_uid, agent_gid, match):
    world = World(agent_uid=agent_uid, agent_gid=agent_gid)
    try:
        with pytest.raises(ValueError, match=match):
            world.start_in_process()
    finally:
        world.stop()


def test_run_dir_reached_through_a_symlink_is_refused(tmp_path):
    base = tmp_path.resolve()
    (base / "real").mkdir()
    (base / "link").symlink_to(base / "real")
    with pytest.raises(ValueError, match="symlink"):
        prepare_run_dir(base / "link" / "run")


def test_config_others_can_write_is_refused(world):
    os.chmod(world.config_path, 0o666)
    with pytest.raises(ValueError, match="config"):
        load_config(world.config_path)


def test_config_reached_through_a_symlink_is_refused(world, tmp_path):
    link = tmp_path / "config.json"
    link.symlink_to(world.config_path)
    with pytest.raises((ValueError, OSError)):
        load_config(link)


def test_world_writes_its_config_private_to_the_executor_user(world):
    assert stat.S_IMODE(world.config_path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    ("fault", "effects", "retry"),
    [
        ("terminal_returned_write", 1, ("refused", "already_done")),
        ("terminal_unknown_write", 0, ("refused", "already_outcome_unknown")),
        ("sign_effect_proof", 0, ("outcome_unknown", "already_issued")),
    ],
)
def test_a_failure_after_the_credential_was_issued_is_never_reported_as_a_refusal(
    world, alice, monkeypatch, fault, effects, retry
):
    from executor import core

    running = world.start_in_process(minter=_FailingMinter()) if fault == "terminal_unknown_write" else None
    running = running or world.start_in_process()
    evidence = running.built.executor._evidence
    real_write = evidence.write
    failing = {"terminal_returned_write": ("terminal", "returned"), "terminal_unknown_write": ("terminal", "unknown")}

    def write(**fields):
        if (fields["event"], fields["outcome"]) == failing.get(fault) and fields.get(
            "error"
        ) != "internal_error_after_issue":
            raise OSError("disk full")
        return real_write(**fields)

    def sign(*arguments):
        raise RuntimeError("signing failed")

    monkeypatch.setattr(evidence, "write", write)
    if fault == "sign_effect_proof":
        monkeypatch.setattr(core, "sign_effect_proof", sign)
    response = world.send(alice, *DEPLOY, "n1")
    assert (response["status"], response["reason"]) == ("outcome_unknown", "internal_error_after_issue")
    assert response["op_id"]
    assert len(world.effects("deploy-api")) == effects
    second = world.send(alice, *DEPLOY, "n1")
    assert (second["status"], second["reason"]) == retry
    assert len(world.effects("deploy-api")) == effects


def test_a_failure_after_issue_leaves_a_terminal_evidence_row(world, alice, monkeypatch):
    from executor import core

    world.start_in_process()

    def sign(*arguments):
        raise RuntimeError("signing failed")

    monkeypatch.setattr(core, "sign_effect_proof", sign)
    world.send(alice, *DEPLOY, "n1")
    terminal = [row for row in world.audit_rows() if row["event"] == "terminal"]
    assert [(row["outcome"], row["executed"], row["error"]) for row in terminal] == [
        ("unknown", False, "internal_error_after_issue")
    ]
