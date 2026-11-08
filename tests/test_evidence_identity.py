import json

import pytest

from demo.agents import Agent
from demo.world import DEPLOY_SCOPE, EXECUTOR_ID, ISSUER_ID, PRINCIPAL, TENANT
from executor.client import send_frame
from executor.protocol import encode_request

ARGS = {"image": "api:1"}


def delegated(world):
    alice, bob = Agent("alice"), Agent("bob")
    world.root_for(alice, purpose="release-bot")
    alice.delegate_to(bob, scope=DEPLOY_SCOPE, budget=10, ttl=600, now=world.now)
    return alice, bob


def test_identity_comes_from_the_verified_chain(world, running):
    alice, bob = delegated(world)
    assert world.send(bob, "deploy.service", "env/staging/api", ARGS, "n1")["status"] == "done"
    for row in world.audit_rows():
        assert row["principal"] == PRINCIPAL
        assert row["actor"] == bob.public_key
        assert row["parent_actor"] == alice.public_key
        assert row["agent_id"] == bob.public_key
        assert row["tenant_id"] == TENANT
        assert row["purpose"] == "release-bot"


def test_root_subject_acting_directly_is_attributed_to_the_root_issuer(world, running, alice):
    world.send(alice, "deploy.service", "env/staging/api", ARGS, "n1")
    row = world.audit_rows()[0]
    assert row["actor"] == alice.public_key
    assert row["parent_actor"] == ISSUER_ID


@pytest.mark.parametrize(
    "field", ["principal", "actor", "parent_actor", "tenant_id", "purpose", "agent_id", "grant_hash"]
)
def test_identity_fields_supplied_by_the_agent_are_refused_and_never_recorded(world, running, alice, field):
    request = alice.request(
        audience=EXECUTOR_ID, now=world.now, tool="deploy.service", resource="env/staging/api", args=ARGS, nonce="n1"
    )
    body = json.loads(encode_request(request))
    body[field] = "forged-value"
    response = send_frame(running.socket_path, json.dumps(body).encode())
    assert response["reason"] == "malformed_request"
    assert world.effects("deploy-api") == []
    assert "forged-value" not in json.dumps(world.audit_rows())


def test_host_is_recorded_as_a_claim_and_changes_no_identity(world, running, alice):
    world.send(alice, "deploy.service", "env/staging/api", ARGS, "n1", host="prod-signer-1")
    for row in world.audit_rows():
        assert row["host"] == "claim:prod-signer-1"
        assert row["actor"] == alice.public_key


def test_trace_id_is_carried_when_well_formed_and_refused_otherwise(world, running, alice):
    trace = "ab" * 16
    assert world.send(alice, "deploy.service", "env/staging/api", ARGS, "n1", trace_id=trace)["trace_id"] == trace
    assert {row["trace_id"] for row in world.audit_rows()} == {trace}
    request = alice.request(
        audience=EXECUTOR_ID, now=world.now, tool="deploy.service", resource="env/staging/api", args=ARGS, nonce="n2"
    )
    body = json.loads(encode_request(request))
    body["trace_id"] = "NOT-HEX"
    assert send_frame(running.socket_path, json.dumps(body).encode())["reason"] == "malformed_request"


def test_unverified_requests_carry_no_identity(world, running):
    rogue = Agent("rogue")
    world.root_for(rogue, tenant="tenant-z")
    assert world.send(rogue, "deploy.service", "env/staging/api", ARGS, "n1")["reason"] == "chain_invalid"
    row = world.audit_rows()[-1]
    assert row["agent_id"] == "unverified"
    for field in ("principal", "actor", "parent_actor", "tenant_id", "task_root", "grant_hash", "purpose"):
        assert field not in row
