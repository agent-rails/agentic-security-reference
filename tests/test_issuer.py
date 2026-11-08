import hashlib
import hmac
import json
import time

import jwt
import pytest
from agent_warrant.encoding import b64u
from agent_warrant.identity import generate_keypair
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from demo.agents import Agent
from demo.world import FULL_SCOPE, ISSUER_ID, TENANT, World
from issuer import (
    IssuanceRefused,
    OidcConfig,
    OidcTaskRootIssuer,
    RemoteJwks,
    StaticJwks,
    TaskRootRequest,
    TenantRule,
)

IDP = "https://idp.example.com/"
AUDIENCE = "task-root-issuer"


@pytest.fixture(scope="module")
def idp_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks_for(private_key, kid="k1"):
    document = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    return {"keys": [{**document, "kid": kid, "use": "sig", "alg": "RS256"}]}


def make_config(**overrides):
    values = {
        "issuer_url": IDP,
        "audience": AUDIENCE,
        "algorithms": ("RS256",),
        "tenant_claim": "org",
        "tenant_map": {"acme": TENANT},
        "tenants": {TENANT: TenantRule(ceiling_scope=FULL_SCOPE, max_budget=500, max_depth=3, max_ttl=3600)},
    }
    return OidcConfig(**{**values, **overrides})


@pytest.fixture
def issuer_key():
    return generate_keypair()


@pytest.fixture
def issuer(idp_key, issuer_key):
    return OidcTaskRootIssuer(
        make_config(), StaticJwks(jwks_for(idp_key)), issuer_key, ISSUER_ID, lambda: 1_800_000_000
    )


def token(idp_key, kid="k1", algorithm="RS256", **claims):
    now = int(time.time())
    payload = {"iss": IDP, "aud": AUDIENCE, "sub": "alice", "org": "acme", "exp": now + 300, "iat": now, **claims}
    payload = {key: value for key, value in payload.items() if value is not None}
    return jwt.encode(payload, idp_key, algorithm=algorithm, headers={"kid": kid})


def request(**overrides):
    values = {
        "task_id": "task-1",
        "purpose": "release-bot",
        "scope": {"tools": ["deploy.*"], "resources": ["env/staging/*"], "max_cost_per_call": 5},
        "budget": 50,
        "max_depth": 2,
        "ttl": 600,
        "subject": Agent("a").public_key,
    }
    return TaskRootRequest(**{**values, **overrides})


def test_valid_token_yields_a_signed_task_root_with_claims_from_the_token(issuer, idp_key):
    root = issuer.issue(token(idp_key), request())
    assert (root.principal, root.tenant_id, root.issuer, root.purpose) == (
        "user:alice",
        TENANT,
        ISSUER_ID,
        "release-bot",
    )
    assert (root.issued_at, root.expires_at, root.budget) == (1_800_000_000, 1_800_000_600, 50)


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.example.com/"},
        {"aud": "someone-else"},
        {"exp": int(time.time()) - 3600},
        {"nbf": int(time.time()) + 3600},
        {"exp": None},
        {"sub": None},
        {"org": "unknown-org"},
        {"org": None},
    ],
)
def test_token_claim_failures_are_refused(issuer, idp_key, claims):
    with pytest.raises(IssuanceRefused):
        issuer.issue(token(idp_key, **claims), request())


def test_token_signed_by_another_key_is_refused(issuer):
    with pytest.raises(IssuanceRefused, match="id token refused"):
        issuer.issue(token(rsa.generate_private_key(public_exponent=65537, key_size=2048)), request())


def test_unknown_kid_is_refused(issuer, idp_key):
    with pytest.raises(IssuanceRefused, match="kid"):
        issuer.issue(token(idp_key, kid="nope"), request())


def test_unsigned_token_is_refused(issuer, idp_key):
    now = int(time.time())
    unsigned = jwt.encode(
        {"iss": IDP, "aud": AUDIENCE, "sub": "alice", "org": "acme", "exp": now + 300},
        None,
        algorithm="none",
        headers={"kid": "k1"},
    )
    with pytest.raises(IssuanceRefused):
        issuer.issue(unsigned, request())


def test_hmac_token_keyed_with_the_public_key_is_refused(issuer, idp_key):
    public_pem = idp_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    now = int(time.time())

    def segment(value):
        return b64u(json.dumps(value).encode())

    signing_input = (
        segment({"alg": "HS256", "typ": "JWT", "kid": "k1"})
        + "."
        + segment({"iss": IDP, "aud": AUDIENCE, "sub": "alice", "org": "acme", "exp": now + 300})
    )
    mac = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    with pytest.raises(IssuanceRefused):
        issuer.issue(signing_input + "." + b64u(mac), request())


def test_token_signed_with_an_algorithm_outside_the_allowlist_is_refused(idp_key, issuer_key):
    ec_key = ec.generate_private_key(ec.SECP256R1())
    document = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(ec_key.public_key()))
    jwks = {"keys": [{**document, "kid": "e1", "use": "sig", "alg": "ES256"}]}
    restricted = OidcTaskRootIssuer(make_config(), StaticJwks(jwks), issuer_key, ISSUER_ID, lambda: 1_800_000_000)
    with pytest.raises(IssuanceRefused):
        restricted.issue(token(ec_key, kid="e1", algorithm="ES256"), request())


def test_request_cannot_exceed_the_tenant_rule(issuer, idp_key):
    good = token(idp_key)
    for overrides in (
        {"scope": {"tools": ["admin.*"], "resources": ["env/staging/*"], "max_cost_per_call": 5}},
        {"scope": {**FULL_SCOPE, "max_cost_per_call": 101}},
        {"budget": 501},
        {"max_depth": 4},
        {"ttl": 3601},
        {"ttl": 0},
    ):
        with pytest.raises(IssuanceRefused):
            issuer.issue(good, request(**overrides))


def test_request_has_no_way_to_name_a_principal_or_tenant():
    fields = set(TaskRootRequest.__dataclass_fields__)
    assert not fields & {"principal", "tenant", "tenant_id", "issuer"}


def test_config_refuses_unsafe_algorithms_and_unruled_tenants():
    with pytest.raises(ValueError, match="algorithms"):
        make_config(algorithms=("HS256",))
    with pytest.raises(ValueError, match="algorithms"):
        make_config(algorithms=("none",))
    with pytest.raises(ValueError, match="TenantRule"):
        make_config(tenant_map={"acme": "tenant-without-rule"})


def test_remote_jwks_requires_https():
    with pytest.raises(ValueError, match="https"):
        RemoteJwks("http://idp.example.com/jwks.json")


def test_end_to_end_oidc_token_to_effect(idp_key, issuer_key):
    world = World(clock=time.time, issuer_key=issuer_key)
    world.start_in_process()
    try:
        issuing = OidcTaskRootIssuer(make_config(), StaticJwks(jwks_for(idp_key)), issuer_key, ISSUER_ID, time.time)
        agent = Agent("alice")
        agent.root = issuing.issue(token(idp_key), request(subject=agent.public_key))
        response = world.send(agent, "deploy.service", "env/staging/api", {"image": "api:1"}, "n1")
        assert response["status"] == "done"
        row = world.audit_rows()[0]
        assert (row["principal"], row["tenant_id"], row["purpose"]) == ("user:alice", TENANT, "release-bot")
    finally:
        world.stop()
