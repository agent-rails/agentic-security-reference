from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from agent_warrant.scope import scope_narrows, validate_scope
from agent_warrant.task_root import MAX_TTL, TaskRoot, issue_task_root
from agent_warrant.trust import PREFIX_DELIMITERS
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SAFE_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"})
REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub")
MAX_LEEWAY_SECONDS = 60
ACCESS_TOKEN_TYPES = frozenset({"at+jwt", "application/at+jwt"})
PRINCIPAL_FORBIDDEN = frozenset(PREFIX_DELIMITERS) | {"*"}


class IssuanceRefused(Exception):
    """The ID token or the request was refused. Nothing was signed."""


class JwksSource(Protocol):
    def signing_key(self, token: str) -> Any:
        """Return the verification key for the token's `kid`, or raise."""
        ...


def _token_kid_and_alg(token: str) -> tuple[str, str]:
    header = jwt.get_unverified_header(token)
    kid, algorithm = header.get("kid"), header.get("alg")
    if not isinstance(kid, str) or not kid:
        raise IssuanceRefused("token has no kid")
    if not isinstance(algorithm, str):
        raise IssuanceRefused("token has no alg")
    return kid, algorithm


def _key_for(key: jwt.PyJWK, algorithm: str) -> Any:
    """A key verifies only the algorithm its JWK names, or the one PyJWT infers from its type when it names none."""
    if key.algorithm_name != algorithm:
        raise IssuanceRefused(f"token alg {algorithm} differs from the key's alg {key.algorithm_name}")
    return key.key


class StaticJwks:
    """Keys from a JWKS document already in hand. Tests use this with a local key set; no network. Every key must
    have a unique string `kid` and, when `use` is given, be a signing key."""

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        entries = jwks.get("keys")
        if not isinstance(entries, list) or not entries:
            raise ValueError("JWKS must have a non-empty keys list")
        self._keys: dict[str, jwt.PyJWK] = {}
        for entry in entries:
            kid = entry.get("kid") if isinstance(entry, dict) else None
            if not isinstance(kid, str) or not kid:
                raise ValueError("every JWKS key needs a string kid")
            if kid in self._keys:
                raise ValueError(f"JWKS has duplicate kid {kid!r}")
            if entry.get("use", "sig") != "sig":
                raise ValueError(f"JWKS key {kid!r} is not a signing key")
            self._keys[kid] = jwt.PyJWK(entry)

    def signing_key(self, token: str) -> Any:
        kid, algorithm = _token_kid_and_alg(token)
        key = self._keys.get(kid)
        if key is None:
            raise IssuanceRefused("no key with the token's kid in the JWKS")
        return _key_for(key, algorithm)


class RemoteJwks:
    """Keys fetched from the identity provider's configured JWKS URL by PyJWT's client (https only, no redirects,
    cached, signing keys only)."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        if not url.startswith("https://"):
            raise ValueError("the JWKS URL must be https")
        self._client = jwt.PyJWKClient(url, timeout=timeout)

    def signing_key(self, token: str) -> Any:
        _, algorithm = _token_kid_and_alg(token)
        return _key_for(self._client.get_signing_key_from_jwt(token), algorithm)


def _is_int(value: Any) -> bool:
    return type(value) is int


@dataclass(frozen=True)
class TenantRule:
    """What one tenant may be issued: the largest scope, budget, depth and lifetime a task root may carry."""

    ceiling_scope: dict[str, Any]
    max_budget: int
    max_depth: int
    max_ttl: int

    def __post_init__(self) -> None:
        problem = validate_scope(self.ceiling_scope)
        if problem:
            raise ValueError(f"ceiling_scope is not a scope: {problem}")
        if not _is_int(self.max_budget) or self.max_budget < 0:
            raise ValueError("max_budget must be a non-negative integer")
        if not _is_int(self.max_depth) or self.max_depth < 1:
            raise ValueError("max_depth must be a positive integer")
        if not _is_int(self.max_ttl) or not 1 <= self.max_ttl <= MAX_TTL:
            raise ValueError(f"max_ttl must be an integer between 1 and {MAX_TTL}")


@dataclass(frozen=True)
class OidcConfig:
    """`issuer_url` and `audience` must equal the token's `iss` and `aud`; `audience` is this issuer's client id.
    The principal is `principal_prefix + claims[principal_claim]`; the prefix ends in ':' and the claim value may
    not contain '*' or any delimiter the executor's trust policy splits prefixes on (':', '/', '.'), so a token
    cannot name a principal in another namespace. The principal claim must therefore be a stable opaque id such as
    `sub` or `oid`; an email address is refused. The tenant is `tenant_map[claims[tenant_claim]]`; a tenant claim not
    in the map is refused. `tenants` maps a tenant id to its `TenantRule`."""

    issuer_url: str
    audience: str
    algorithms: tuple[str, ...]
    tenant_claim: str
    tenant_map: Mapping[str, str]
    tenants: Mapping[str, TenantRule]
    principal_claim: str = "sub"
    principal_prefix: str = "user:"
    leeway_seconds: int = 30

    def __post_init__(self) -> None:
        if not self.algorithms or not set(self.algorithms) <= SAFE_ALGORITHMS:
            raise ValueError(f"algorithms must be a non-empty subset of {sorted(SAFE_ALGORITHMS)}")
        if set(self.tenant_map.values()) - set(self.tenants):
            raise ValueError("tenant_map names a tenant with no TenantRule")
        if not _is_int(self.leeway_seconds) or not 0 <= self.leeway_seconds <= MAX_LEEWAY_SECONDS:
            raise ValueError(f"leeway_seconds must be an integer between 0 and {MAX_LEEWAY_SECONDS}")
        if len(self.principal_prefix) < 2 or not self.principal_prefix.endswith(":"):
            raise ValueError("principal_prefix must be a non-empty name ending in ':'")


@dataclass(frozen=True)
class TaskRootRequest:
    task_id: str
    purpose: str
    scope: dict[str, Any]
    budget: int
    max_depth: int
    ttl: int
    subject: str


class OidcTaskRootIssuer:
    """Turns a verified OIDC ID token into a signed TaskRoot.

    The token proves who the human is. Signature, `iss`, `aud`, `exp` and `nbf` are checked by PyJWT against keys
    from the configured identity provider; `exp`, `iss`, `aud` and `sub` are required. Principal and tenant are
    derived from claims by configuration, never from the request. The request may ask for less than the tenant's
    rule allows and never more. An identity provider such as Entra or Okta sits in front of this issuer and
    produces the ID token; the executor's trust policy lists this issuer, not the provider.

    One clock decides time: `exp`, `nbf` and `iat` are checked against the issuer's clock, and a task root never
    outlives the ID token it came from. The guard against tokens meant for someone else is the audience: `aud`
    must include this client, a token whose authorized party (`azp`) is another client is refused, and a token
    with several audiences must name this client as `azp`. Tokens typed as access tokens (`typ` at+jwt, with any
    media-type parameters) are also refused, but most providers type their access tokens plain "JWT", so `typ`
    alone does not tell them apart.

    Not defended: the caller chooses the task root's subject key, and an ID token can be exchanged for several
    task roots until it expires. Whoever holds a valid ID token, including a thief, can mint roots bound to a key
    of their choosing for the rest of that token's lifetime."""

    def __init__(
        self,
        config: OidcConfig,
        jwks: JwksSource,
        signing_key: Ed25519PrivateKey,
        issuer_id: str,
        clock: Callable[[], float],
    ) -> None:
        self._config = config
        self._jwks = jwks
        self._signing_key = signing_key
        self._issuer_id = issuer_id
        self._clock = clock

    def _claims(self, id_token: str, now: int) -> dict[str, Any]:
        try:
            typ = jwt.get_unverified_header(id_token).get("typ")
            if isinstance(typ, str) and typ.split(";")[0].strip().lower() in ACCESS_TOKEN_TYPES:
                raise IssuanceRefused("an access token is not an ID token")
            key = self._jwks.signing_key(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer_url,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except IssuanceRefused:
            raise
        except (jwt.PyJWTError, ValueError, KeyError) as err:
            raise IssuanceRefused(f"id token refused: {err}") from None
        self._check_times(claims, now)
        self._check_authorized_party(claims)
        return claims

    def _check_times(self, claims: Mapping[str, Any], now: int) -> None:
        leeway = self._config.leeway_seconds
        for name in ("exp", "nbf", "iat"):
            if name in claims and not _is_int(claims[name]):
                raise IssuanceRefused(f"id token refused: {name} must be an integer")
        if claims["exp"] + leeway <= now:
            raise IssuanceRefused("id token refused: token has expired")
        if claims.get("nbf", now) - leeway > now:
            raise IssuanceRefused("id token refused: token is not yet valid")
        if claims.get("iat", now) - leeway > now:
            raise IssuanceRefused("id token refused: token was issued in the future")

    def _check_authorized_party(self, claims: Mapping[str, Any]) -> None:
        audience, azp = claims["aud"], claims.get("azp")
        if azp is not None and azp != self._config.audience:
            raise IssuanceRefused("id token refused: azp names another client")
        if isinstance(audience, list) and len(audience) > 1 and azp is None:
            raise IssuanceRefused("id token refused: a token with several audiences must name this client as azp")

    def _principal(self, claims: Mapping[str, Any]) -> str:
        value = claims.get(self._config.principal_claim)
        if not isinstance(value, str) or not value:
            raise IssuanceRefused("principal claim is missing")
        if PRINCIPAL_FORBIDDEN & set(value):
            raise IssuanceRefused(f"principal claim may not contain any of {''.join(sorted(PRINCIPAL_FORBIDDEN))}")
        return self._config.principal_prefix + value

    def issue(self, id_token: str, request: TaskRootRequest) -> TaskRoot:
        now = int(self._clock())
        claims = self._claims(id_token, now)
        tenant_value = claims.get(self._config.tenant_claim)
        tenant = self._config.tenant_map.get(tenant_value) if isinstance(tenant_value, str) else None
        if tenant is None:
            raise IssuanceRefused("tenant claim is missing or not mapped")
        principal = self._principal(claims)
        rule = self._config.tenants[tenant]
        scope = copy.deepcopy(request.scope)
        if not scope_narrows(rule.ceiling_scope, scope):
            raise IssuanceRefused("requested scope is outside the tenant's ceiling")
        if not _is_int(request.budget) or not 0 <= request.budget <= rule.max_budget:
            raise IssuanceRefused(f"budget must be an integer between 0 and {rule.max_budget}")
        if not _is_int(request.max_depth) or not 1 <= request.max_depth <= rule.max_depth:
            raise IssuanceRefused(f"max_depth must be an integer between 1 and {rule.max_depth}")
        if not _is_int(request.ttl) or not 1 <= request.ttl <= rule.max_ttl:
            raise IssuanceRefused(f"ttl must be an integer between 1 and {rule.max_ttl} seconds")
        expires_at = min(now + request.ttl, claims["exp"])
        if expires_at <= now:
            raise IssuanceRefused("id token expires before a task root could be used")
        try:
            return issue_task_root(
                self._signing_key,
                issuer=self._issuer_id,
                task_id=request.task_id,
                tenant_id=tenant,
                principal=principal,
                purpose=request.purpose,
                budget=request.budget,
                max_depth=request.max_depth,
                issued_at=now,
                expires_at=expires_at,
                scope=scope,
                subject=request.subject,
            )
        except ValueError as err:
            raise IssuanceRefused(f"task root refused: {err}") from None
