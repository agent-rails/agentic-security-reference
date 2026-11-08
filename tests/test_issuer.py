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
NOW = 1_800_000_000


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
    return OidcTaskRootIssuer(make_config(), StaticJwks(jwks_for(idp_key)), issuer_key, ISSUER_ID, lambda: NOW)


def token(idp_key, kid="k1", algorithm="RS256", now=NOW, headers=None, **claims):
    payload = {"iss": IDP, "aud": AUDIENCE, "sub": "alice", "org": "acme", "exp": now + 3600, "iat": now, **claims}
    payload = {key: value for key, value in payload.items() if value is not None}
    return jwt.encode(payload, idp_key, algorithm=algorithm, headers={"kid": kid, **(headers or {})})


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
        {"exp": NOW - 3600},
        {"nbf": NOW + 3600},
        {"iat": NOW + 3600},
        {"exp": True},
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
    now = NOW
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
    now = NOW

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
    restricted = OidcTaskRootIssuer(make_config(), StaticJwks(jwks), issuer_key, ISSUER_ID, lambda: NOW)
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
        {"ttl": True},
        {"budget": "5"},
        {"max_depth": 2.0},
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
        agent.root = issuing.issue(token(idp_key, now=int(time.time())), request(subject=agent.public_key))
        response = world.send(agent, "deploy.service", "env/staging/api", {"image": "api:1"}, "n1")
        assert response["status"] == "done"
        row = world.audit_rows()[0]
        assert (row["principal"], row["tenant_id"], row["purpose"]) == ("user:alice", TENANT, "release-bot")
    finally:
        world.stop()


def test_task_root_never_outlives_the_id_token(issuer, idp_key):
    root = issuer.issue(token(idp_key, exp=NOW + 5), request(ttl=600))
    assert (root.issued_at, root.expires_at) == (NOW, NOW + 5)


def test_token_expired_within_the_leeway_is_refused_rather_than_minting_an_expired_root(issuer, idp_key):
    with pytest.raises(IssuanceRefused, match="expire"):
        issuer.issue(token(idp_key, exp=NOW - 5), request())


def test_token_times_are_checked_against_the_issuer_clock_not_wall_time(idp_key, issuer_key):
    later = OidcTaskRootIssuer(make_config(), StaticJwks(jwks_for(idp_key)), issuer_key, ISSUER_ID, lambda: NOW + 7200)
    with pytest.raises(IssuanceRefused, match="expired"):
        later.issue(token(idp_key), request())


@pytest.mark.parametrize(
    "typ", ["at+jwt", "AT+JWT", "application/at+jwt", " at+jwt", "at+jwt ", "at+jwt;v=1", "application/at+jwt; q=1"]
)
def test_access_token_is_refused(issuer, idp_key, typ):
    with pytest.raises(IssuanceRefused, match="access token"):
        issuer.issue(token(idp_key, headers={"typ": typ}), request())


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": ["other-client", AUDIENCE], "azp": "other-client"},
        {"aud": ["other-client", AUDIENCE]},
        {"azp": "other-client"},
    ],
)
def test_token_issued_to_another_client_is_refused(issuer, idp_key, claims):
    with pytest.raises(IssuanceRefused, match="azp"):
        issuer.issue(token(idp_key, **claims), request())


def test_token_with_this_client_as_authorized_party_is_accepted(issuer, idp_key):
    root = issuer.issue(token(idp_key, aud=["other-client", AUDIENCE], azp=AUDIENCE), request())
    assert root.principal == "user:alice"


@pytest.mark.parametrize("leeway", [-1, 61, 10**9, True, 1.5])
def test_config_refuses_an_unsafe_leeway(leeway):
    with pytest.raises(ValueError, match="leeway"):
        make_config(leeway_seconds=leeway)


@pytest.mark.parametrize("prefix", ["", "user", "user/"])
def test_config_refuses_a_principal_prefix_without_a_delimiter(prefix):
    with pytest.raises(ValueError, match="principal_prefix"):
        make_config(principal_prefix=prefix)


@pytest.mark.parametrize("subject", ["alice:admin", "*", "svc:deployer", "acme/admin", "acme.admin"])
def test_principal_claim_with_a_delimiter_or_wildcard_is_refused(issuer, idp_key, subject):
    with pytest.raises(IssuanceRefused, match="principal"):
        issuer.issue(token(idp_key, sub=subject), request())


def test_principal_claim_must_name_a_key_trust_policy_cannot_split():
    from agent_warrant.trust import PREFIX_DELIMITERS

    from issuer.oidc import PRINCIPAL_FORBIDDEN

    assert set(PREFIX_DELIMITERS) | {"*"} <= PRINCIPAL_FORBIDDEN


def test_email_cannot_be_a_principal_even_when_verified(idp_key, issuer_key):
    by_email = OidcTaskRootIssuer(
        make_config(principal_claim="email"), StaticJwks(jwks_for(idp_key)), issuer_key, ISSUER_ID, lambda: NOW
    )
    with pytest.raises(IssuanceRefused, match="principal"):
        by_email.issue(token(idp_key, email="ceo@acme.example", email_verified=True), request())


@pytest.mark.parametrize(
    "rule",
    [
        {"max_budget": -1},
        {"max_depth": 0},
        {"max_ttl": 86401},
        {"max_ttl": True},
        {"ceiling_scope": {"tools": "deploy.*"}},
    ],
)
def test_tenant_rule_refuses_values_outside_what_a_task_root_can_carry(rule):
    values = {"ceiling_scope": FULL_SCOPE, "max_budget": 500, "max_depth": 3, "max_ttl": 3600}
    with pytest.raises(ValueError):
        TenantRule(**{**values, **rule})


def test_issued_root_does_not_share_the_request_scope(issuer, idp_key):
    asked = request()
    root = issuer.issue(token(idp_key), asked)
    asked.scope["tools"].append("admin.*")
    assert root.scope["tools"] == ["deploy.*"]


def test_jwks_key_whose_alg_differs_from_the_token_alg_is_refused(idp_key, issuer_key):
    jwks = jwks_for(idp_key)
    pss = OidcTaskRootIssuer(
        make_config(algorithms=("RS256", "PS256")), StaticJwks(jwks), issuer_key, ISSUER_ID, lambda: NOW
    )
    with pytest.raises(IssuanceRefused, match="alg"):
        pss.issue(token(idp_key, algorithm="PS256"), request())


def test_token_without_a_kid_is_refused(issuer, idp_key):
    payload = {"iss": IDP, "aud": AUDIENCE, "sub": "alice", "org": "acme", "exp": NOW + 3600, "iat": NOW}
    with pytest.raises(IssuanceRefused, match="kid"):
        issuer.issue(jwt.encode(payload, idp_key, algorithm="RS256"), request())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda keys: [{**keys[0], "use": "enc"}],
        lambda keys: [{key: value for key, value in keys[0].items() if key != "kid"}],
        lambda keys: [keys[0], keys[0]],
    ],
)
def test_jwks_refuses_encryption_keys_missing_kids_and_duplicate_kids(idp_key, mutate):
    with pytest.raises(ValueError, match="JWKS"):
        StaticJwks({"keys": mutate(jwks_for(idp_key)["keys"])})
