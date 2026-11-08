# Decisions

Each entry states the decision and the reason. Dates are 2026.

## Step 0

- Outcome sought (2026-11-07): a public reference architecture with an open implementation that others can cite and adopt. Client deployments are proof points; a product stays a later decision.
- Assumption rejected: that human and service IAM transfers to agents. Agents are ephemeral, spawn copies, act for others at machine speed and are steerable by what they read. The task and delegation chain is the unit of authority: short-lived, narrowed per hop, bound to the delegating human. Agent identity is kept for accountability.
- Adopt formats and semantics, not infrastructure: W3C Trace Context and OpenTelemetry GenAI naming as a target (status Development), OAuth 2.0 Token Exchange on-behalf-of semantics carried by signed delegation records, SPIFFE-style naming where useful, alignment with MCP authorization.
- Not adopted now: SPIRE, an authorization server per hop, OPA or Cedar, a central decision service, a gateway in the request path, a model judge on the request path, a networked ledger before multi-host is needed, migrating HMAC schemes to Ed25519.

## B1: multi-hop delegation

Hash-chained delegation records. Each link embeds its parent's hash and is signed by the parent holder; scope and budget only narrow. One ledger per task root holds revocation status and budget; an unreachable ledger refuses the effect. RFC 8693 issuer-per-hop was rejected because it needs an online authorization server at every hop.

## B2: credential custody

Agents and endpoints hold no long-lived credentials. A credential injector at the effect keeps the secrets and mints a short-lived, operation-bound credential only after the checks pass. Modes are advisory, enforced and isolated, stated plainly in the README.

## The two infrastructure exceptions

1. The credential injector, running inside the executor process.
2. The task ledger.

Everything else is formats and libraries.

## Warrant and guard glue lives here

The adapters between agent-warrant and agent-guard are in this repository's `executor/` package, not in an agent-guard extra. agent-guard imports nothing from agent-warrant, and a test checks it (`tests/test_pins.py::test_agent_guard_core_does_not_import_agent_warrant`). This replaces the earlier plan to ship a `[warrant]` extra in agent-guard.

## Executor design

- Operation id: derived by the executor as a hash of tenant, task, leaf record and request digest, encoded as canonical JSON so that delimiters cannot be shifted between fields. There is no trusted-caller path to supply one, because the only caller on the socket is the agent; a second authenticated socket would be needed and is not built. The leaf record is included so two holders sending the same request are two operations.
- Idempotency: the agent chooses a nonce. The same nonce from the same holder is the same operation and is refused as already done; a new nonce is a new operation.
- Two digests: the agent's leaf proof binds the request digest, which it can compute. The credential binds the operation digest, which covers executor-chosen fields (cost, expiry, verdict).
- Cost: a versioned schedule owned by the executor's configuration. A tool with no entry is refused.
- One credential injector per target audience, sharing one issuance log and one suspension directory, because an injector carries a single audience.
- Any failure after a credential was issued, including a definite refusal by the target, is recorded as an unknown outcome. The ledger has no state for "issued, known not performed", and its cost is never credited back automatically.
- Requests that fail verification are recorded as `unverified` with no identity fields.
- Strictness over leniency: a request with an unknown field is refused, including any identity field, rather than having the field ignored.
- The ledger is opened, never created, by the executor. The demo creates it as the operator would.

## Separate-user mode

- The agent runs as its own non-root OS user (`agent_uid`) in a group the executor belongs to (`agent_gid`). The run directory is 0710 and the socket 0660, both owned by that group, so other local users cannot reach the socket; the kernel's peer credentials then admit only `agent_uid`. A world-open socket with only the peer check was rejected because any local user could fill the listen backlog.
- `run_dir` must be an absolute path with no symlink in it, and no directory above it may be owned by another user or writable by others unless sticky. The configuration must be owned by the executor's user and not writable by others.

## Issuer

- A small OIDC task-root issuer maps verified ID-token claims to principal and tenant by configuration. It uses PyJWT for token verification; no token parsing is hand-written.
- Entra, Okta and similar providers sit in front of the issuer and produce the ID token. They are not issuers in the executor's trust policy.
- One clock: `exp`, `nbf` and `iat` are checked against the issuer's clock, with leeway of at most 60 seconds, and a root's expiry is capped at the token's `exp`.
- The guard against tokens meant for another client is the audience and `azp`, not `typ`: most providers type access tokens plain `JWT`.
- The principal claim must be a stable opaque id such as `sub` or `oid`. It may not contain `*` or any delimiter the trust policy splits prefixes on, so email addresses are refused.

## Detection responses

Alerts are routed through agent-guard's authenticated alert sink. A suspend alert suspends injection. A revoke alert revokes the task root binding in the ledger, which stops every chain below it.

- Each detected event is keyed by kind, persona, tenant, time and task roots, plus the tool or resource for a first-use alert, and recorded only after its action reaches a final outcome. A time cursor was tried and rejected: it dropped hour-bucket alerts, alerts whose action failed, and every alert after a future-dated row.
- Delivery is at least once, failing toward stopping.
- Routing refuses to act on an audit log with a row that fails verification or parsing, rather than acting on what is left; an operator repairs the log ([OPERATIONS.md](OPERATIONS.md)).

## Tooling

- Libraries are pinned to commit SHAs; actions are pinned to commit SHAs; the token is read-only.
- The type checker is mypy in strict mode over `executor/` and `issuer/`.
- Deferred: a weekly drift job against the libraries' main branches, and an HTML trace report.
