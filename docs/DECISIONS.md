# Decisions

## Authority

Human and service IAM do not transfer unchanged to an agent that can delegate work and be steered by what it reads. A signed task root and its narrowing delegation chain carry authority. The agent's public key identifies the actor for attribution. The executor, rather than the agent, decides whether an effect is allowed.

This reference does not add an authorization server per hop, a central policy service, or a networked ledger. Those components would add operational dependencies without changing the single-host demonstration.

## Multi-hop delegation

Each delegation link embeds its parent's hash and is signed by the parent holder. Scope and budget can only narrow. The ledger tracks revocation and budget for each task root; an unreachable ledger refuses the effect. An issuer at every hop was rejected because it would require an online authorization server for each delegation.

## Credential custody

Agents hold private signing keys for delegation proofs. The executor keeps downstream credential material and mints an operation-bound credential only after authorization succeeds. The fake targets hold the secret needed to verify it. Real target adapters must restrict responses and errors before returning them to agents.

## Warrant and guard glue lives here

The adapters between agent-warrant and agent-guard belong in this repository's `executor/` package. agent-guard has no dependency on agent-warrant, as checked by `tests/test_pins.py::test_agent_guard_core_does_not_import_agent_warrant`.

## Executor design

- The executor derives the operation id from tenant, task, leaf record and request digest. Canonical JSON prevents delimiter ambiguity. The agent cannot supply an operation id, and the leaf record distinguishes two holders sending the same request.
- The agent chooses a nonce. A retry with the same nonce reuses the operation id and its stored state; an issued but unminted operation may resume once. A new nonce creates a new operation, so a lost response must be retried with the original nonce.
- The leaf proof binds the agent-computable request digest. The credential binds the operation digest, which also includes executor-chosen cost, expiry and verdict.
- The executor owns a versioned cost schedule and refuses a tool without a cost entry.
- Each tool has an injector bound to its target audience because an injector carries one audience. Injectors share an issuance log and a suspension directory.
- A failure after a credential has been issued, including a definite target refusal, is recorded as an unknown outcome. The ledger has no state for "issued, known not performed", so cost is not credited automatically.
- Requests that fail verification are recorded as `unverified` with no identity fields.
- The decoder refuses unknown request fields, including identity fields supplied by an agent.
- The ledger is opened, never created, by the executor. The demo creates it as the operator would.

## Separate-user mode

- The agent runs as its own non-root OS user (`agent_uid`) in a group the executor belongs to (`agent_gid`). The run directory is 0710 and the socket 0660, both owned by that group, so other local users cannot reach the socket; the kernel's peer credentials then admit only `agent_uid`. A world-open socket with only the peer check was rejected because any local user could fill the listen backlog.
- `run_dir` must be an absolute path with no symlink in it, and no directory above it may be owned by another user or writable by others unless sticky. The configuration must be owned by the executor's user and not writable by others.

## Issuer

- A small OIDC task-root issuer maps verified ID-token claims to principal and tenant by configuration. It uses PyJWT for token verification; no token parsing is hand-written.
- Entra, Okta and similar providers sit in front of the issuer and produce the ID token. They are not issuers in the executor's trust policy.
- The issuer checks `exp`, `nbf` and `iat` against its clock with up to 60 seconds of leeway. A task root cannot outlive the ID token.
- Audience and `azp` checks reject tokens meant for another client. The `typ` field alone is insufficient because access tokens may be typed plain `JWT`.
- The principal claim must be a stable opaque id such as `sub` or `oid`. It may not contain `*` or any delimiter the trust policy splits prefixes on, so email addresses are refused.

## Detection responses

Alerts are routed through agent-guard's authenticated alert sink. A suspend alert suspends injection. A revoke alert revokes the task root binding in the ledger, which stops every chain below it.

- Each detected event is keyed by kind, persona, tenant, time and task roots, plus the tool or resource for a first-use alert, and recorded only after its action reaches a final outcome. A time cursor was rejected because it drops hour-bucket alerts, alerts whose action failed, and every alert after a future-dated row.
- Alert actions have at-least-once delivery. An action may repeat after a crash before its result is recorded.
- Routing refuses to act on an audit log with a row that fails verification or parsing, rather than acting on what is left; an operator repairs the log ([OPERATIONS.md](OPERATIONS.md)).

## Reproducible builds

CI installs from the hash-locked `requirements-ci.txt`; GitHub Actions are pinned to commit SHAs. The lock covers Python packages, not the interpreter, pip, or release attestations. After changing dependencies, regenerate it with `uv pip compile pyproject.toml requirements-ci.in --extra dev --universal --python-version 3.13 --generate-hashes --no-header --annotation-style line -o requirements-ci.txt`. `tests/test_pins.py` checks direct and build requirements against the lock. Strict mypy covers `executor/` and `issuer/`; `demo/` and `live/` run under pytest.
