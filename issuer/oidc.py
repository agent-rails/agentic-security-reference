from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from agent_warrant.scope import scope_narrows
from agent_warrant.task_root import TaskRoot, issue_task_root
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SAFE_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"})
REQUIRED_CLAIMS = ("exp", "iss", "aud", "sub")


class IssuanceRefused(Exception):
    """The ID token or the request was refused. Nothing was signed."""


class JwksSource(Protocol):
    def signing_key(self, token: str) -> Any:
        """Return the verification key for the token's `kid`, or raise."""
        ...


class StaticJwks:
    """Keys from a JWKS document already in hand. Tests use this with a local key set; no network."""

    def __init__(self, jwks: Mapping[str, Any]) -> None:
        self._keys = jwt.PyJWKSet.from_dict(dict(jwks))

    def signing_key(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        for key in self._keys.keys:
            if key.key_id == kid:
                return key.key
        raise IssuanceRefused("no key with the token's kid in the JWKS")


class RemoteJwks:
    """Keys fetched from the identity provider's configured JWKS URL by PyJWT's client (https only, cached)."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        if not url.startswith("https://"):
            raise ValueError("the JWKS URL must be https")
        self._client = jwt.PyJWKClient(url, timeout=timeout)

    def signing_key(self, token: str) -> Any:
        return self._client.get_signing_key_from_jwt(token).key


@dataclass(frozen=True)
class TenantRule:
    """What one tenant may be issued: the largest scope, budget, depth and lifetime a task root may carry."""

    ceiling_scope: dict[str, Any]
    max_budget: int
    max_depth: int
    max_ttl: int


@dataclass(frozen=True)
class OidcConfig:
    """`issuer_url` and `audience` must equal the token's `iss` and `aud`. The principal is
    `principal_prefix + claims[principal_claim]`. The tenant is `tenant_map[claims[tenant_claim]]`; a tenant
    claim not in the map is refused. `tenants` maps a tenant id to its `TenantRule`."""

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

    Not defended: an ID token can be exchanged for several task roots until it expires."""

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

    def _claims(self, id_token: str) -> dict[str, Any]:
        try:
            key = self._jwks.signing_key(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=list(self._config.algorithms),
                audience=self._config.audience,
                issuer=self._config.issuer_url,
                leeway=self._config.leeway_seconds,
                options={"require": list(REQUIRED_CLAIMS), "verify_signature": True},
            )
        except IssuanceRefused:
            raise
        except (jwt.PyJWTError, ValueError, KeyError) as err:
            raise IssuanceRefused(f"id token refused: {err}") from None
        return claims

    def issue(self, id_token: str, request: TaskRootRequest) -> TaskRoot:
        claims = self._claims(id_token)
        tenant_value = claims.get(self._config.tenant_claim)
        tenant = self._config.tenant_map.get(tenant_value) if isinstance(tenant_value, str) else None
        if tenant is None:
            raise IssuanceRefused("tenant claim is missing or not mapped")
        principal_value = claims.get(self._config.principal_claim)
        if not isinstance(principal_value, str) or not principal_value:
            raise IssuanceRefused("principal claim is missing")
        rule = self._config.tenants[tenant]
        if not scope_narrows(rule.ceiling_scope, request.scope):
            raise IssuanceRefused("requested scope is outside the tenant's ceiling")
        if not 0 <= request.budget <= rule.max_budget:
            raise IssuanceRefused(f"budget must be between 0 and {rule.max_budget}")
        if not 1 <= request.max_depth <= rule.max_depth:
            raise IssuanceRefused(f"max_depth must be between 1 and {rule.max_depth}")
        if not 1 <= request.ttl <= rule.max_ttl:
            raise IssuanceRefused(f"ttl must be between 1 and {rule.max_ttl} seconds")
        now = int(self._clock())
        try:
            return issue_task_root(
                self._signing_key,
                issuer=self._issuer_id,
                task_id=request.task_id,
                tenant_id=tenant,
                principal=self._config.principal_prefix + principal_value,
                purpose=request.purpose,
                budget=request.budget,
                max_depth=request.max_depth,
                issued_at=now,
                expires_at=now + request.ttl,
                scope=request.scope,
                subject=request.subject,
            )
        except ValueError as err:
            raise IssuanceRefused(f"task root refused: {err}") from None
