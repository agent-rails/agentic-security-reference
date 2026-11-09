# Threat model

## Assumptions

- The agent is a steerable, untrusted insider. It may be compromised, may reason about the controls, and may send any bytes.
- The executor, the ledger file, the issuer key, the audit key and the target secrets are trusted. Compromise of the executor is total.
- Issuers are trusted only within the allowance the executor's trust policy gives them.

## Defended

Each row cites a test that exercises the defense under its fixture. Where the defense is only partly tested, the row says so.

| Threat | Defense | Test |
|---|---|---|
| Agent receives an executor service credential through the request path | the stateless demo agent's argv, environment and responses contain no executor credential; agent tooling still holds its own signing key | `tests/test_enforced_process.py::test_stateless_agent_receives_no_executor_secret_and_still_gets_effect`, `tests/test_enforced_process.py::test_response_never_carries_a_credential` |
| Agent reads the executor's files | in separate-user mode the agent runs as another OS user; the executor refuses secrets, keys and a ledger that are not mode 0600, and the socket admits only that user, checked against the kernel's peer credentials. The configuration and audit log are closed to the agent only if the deployer makes them so; the test checks that every file its fixture creates is unreadable to the agent | `tests/test_separate_user.py::test_agent_running_as_another_user_cannot_read_secrets_but_gets_its_effect`, `tests/test_separate_user.py::test_executor_user_is_not_an_allowed_peer_in_separate_user_mode` |
| Another local user reaches the socket | in separate-user mode the socket directory and socket are open only to the agent group | `tests/test_separate_user.py::test_user_outside_the_agent_group_cannot_reach_the_socket` |
| Agent claims an identity, tenant or cost | the strict decoder refuses unknown fields; identity comes from the verified chain; cost comes from a policy-owned schedule | `tests/test_evidence_identity.py::test_identity_fields_supplied_by_the_agent_are_refused_and_never_recorded`, `tests/test_executor.py::test_agent_cannot_state_its_own_cost` |
| Agent chooses or collides an operation id | the wire request has no `op_id`; the executor derives it from tenant, task, leaf record and request | `tests/test_executor.py::test_wire_request_has_no_op_id_field`, `tests/test_executor.py::test_two_holders_sending_the_same_request_are_two_operations` |
| Replaying a request still in flight | the second copy is refused as in progress and leaves the ledger alone | `tests/test_executor.py::test_replay_while_the_first_request_is_in_flight_leaves_the_first_one_alone` |
| Slow or numerous connections | a frame must arrive before an absolute deadline; connections over a fixed cap are closed | `tests/test_executor.py::test_frame_must_arrive_before_an_absolute_deadline`, `tests/test_executor.py::test_connections_over_the_cap_are_closed_and_service_recovers` |
| A model talked into an action outside its task | the executor checks the leaf scope whatever the model decides; shown live in [LIVE_RUN.md](LIVE_RUN.md), where a model told to obey an injected document attempted a withdrawal and was refused | `tests/test_executor.py::test_tool_outside_scope_is_refused`, `tests/test_live.py::test_injected_withdrawal_is_refused_as_out_of_scope` |
| Request altered after the agent signed its proof | the leaf proof binds the request digest and the executor's audience | `tests/test_executor.py::test_proof_for_another_request_is_refused`, `tests/test_executor.py::test_proof_addressed_to_another_verifier_is_refused` |
| Validly signed root from an issuer that may not assert it | executor trust policy: listed issuer, tenant, principal, budget | `demo/scenarios.py::rogue_issuer` |
| Forged or mis-claimed ID token | signature, issuer, audience, expiry, not-before and required claims are checked against the issuer's clock; algorithm allowlist; claims-to-tenant mapping; ceilings per tenant | `tests/test_issuer.py` |
| Task root outliving the ID token | the root's expiry is capped at the token's `exp` | `tests/test_issuer.py::test_task_root_never_outlives_the_id_token` |
| A token meant for another client | `azp` must be this client when present, and a token with several audiences must name it; tokens typed `at+jwt` are refused, but `typ` alone does not separate access tokens typed plain `JWT` | `tests/test_issuer.py::test_token_issued_to_another_client_is_refused`, `tests/test_issuer.py::test_access_token_is_refused` |
| A claim naming a principal in another namespace | the principal claim may not contain `*` or any trust-prefix delimiter (`:`, `/`, `.`) | `tests/test_issuer.py::test_principal_claim_with_a_delimiter_or_wildcard_is_refused` |
| Spending past a budget | link caps and the task pool are reserved in one ledger transaction (agent-warrant); the scenario shows the caps one request at a time, and concurrent spending is not tested here | `demo/scenarios.py::budget_exhaustion` |
| Repeating a request | the same nonce from the same holder never performs a second effect; while the chain is valid it gets the stored state (see lost responses below) | `tests/test_executor.py::test_identical_request_is_not_performed_twice`, `tests/test_executor.py::test_identical_request_in_a_later_second_returns_the_stored_state` |
| Delegation outliving a revocation | revoking a root, link, task or tenant stops later requests | `demo/scenarios.py::root_revocation_cascade`, `demo/scenarios.py::mid_chain_revocation`, `tests/test_operator.py::test_revoking_a_task_or_a_tenant_stops_the_chain` |
| A copied credential used elsewhere | the target refuses another holder key, another operation, altered arguments, a reuse and an expired credential | `demo/scenarios.py::stolen_credential` |
| Fault between steps | after a restart from the state on disk, no second credential is minted for one operation; an unknown outcome is surfaced and its cost stays spent. The faults are raised inside the process; a killed process is not simulated | `demo/scenarios.py::crash_recovery` |
| Tampered evidence feeding the detector | the operator refuses to route any alert while a row fails verification or parsing | `tests/test_operator.py::test_tampered_audit_rows_are_not_trusted_by_the_detector` |
| One alert acting twice | each detected event is recorded once its action reaches a final outcome, so a rescan does not re-suspend after an authorized resume | `tests/test_operator.py::test_rescanning_the_same_log_after_resume_does_not_suspend_again` |

## Not defended, or defended only in part

### Credential and network boundaries

- Binding of the credential is enforced only where the target verifies the executor proof and the operation digest. A target that accepts any bearer value gets no such protection. Such a target should receive a short-lived, narrow token held only by the executor; that path is not built here.
- Inventory covers only agents whose effects pass the executor or a guard. Without an egress proxy, an agent with network access can reach targets directly. Enforced mode requires egress to be denied outside this code.
- Without `agent_uid` and `agent_gid`, the agent runs as the executor's OS user and can read its secrets and ledger or alter its stop state. This is not a custody boundary. Separate-user mode is tested on Linux in CI; macOS tests only the same-user peer check. The operator runs as the executor's user.
- Target results and errors are forwarded without filtering. Real target adapters must restrict returned fields and error details so they cannot disclose credentials.
- Prompt injection, memory poisoning, agent-side code execution and supply-chain compromise of agent tooling are not prevented. The executor limits the effects a compromised agent can request.

### Identity and evidence

- An agent's public key identifies it for attribution without attesting to its software. The `host` field and agent-supplied `trace_id` are claims; the executor generates `call_id`.
- Records carry `tenant_id`, and ledger tasks are keyed by tenant. Evidence is written to one file. Per-tenant partitioning and hosted multi-tenancy are not built.
- HMAC protects individual audit rows against alteration by parties without the key. A compromised producer can sign records or suppress them. Deleted or truncated rows leave no detectable gap, and no external append-only sink is built.
- One ID token can mint several task roots until it expires. The caller chooses each root's subject key, so anyone holding the token can mint roots for a key they control. Roots cannot outlive the token.
- Issuer refusals expose underlying errors, such as a JWKS fetch failure. A fronting service should log the detail and return a generic refusal.

### Execution and recovery

- Revocation and budgets apply only to executors that consult the same ledger. The ledger is one SQLite file on one host; a multi-host deployment needs a shared ledger implementation.
- Issued credentials live until their ttl, 30 seconds in the demo configuration; suspension and revocation affect new ones.
- A lost response must be retried with the same nonce. A new nonce creates a new operation and can perform the effect again. A real target should also deduplicate on a business key.
- A same-nonce retry uses the stored operation state while the chain remains valid. It returns `in_progress` during a call, `already_done` or `already_outcome_unknown` after completion, or `already_released` when an unissued reservation expired. A revoked or expired chain is refused as `chain_invalid` first. An issued operation that has not minted a credential may resume and perform its effect once (`tests/test_executor.py::test_retry_after_a_crash_between_marking_issued_and_minting_runs_once`, `tests/test_executor.py::test_retry_after_the_reservation_expired_unissued_is_refused_as_released`).
- A crash inside `mark_issued` can persist the issued state while the first call returns a refusal. After issuance, mint failures and errors during or after the target call yield `outcome_unknown`; other injector refusals remain refusals. An evidence-write failure may leave an executed effect without a terminal evidence row.
- Two executor processes sharing one ledger can derive different expiries for the same new request in different seconds. The ledger then refuses the second reservation, avoiding another effect. This was reproduced against the ledger, not with two executor processes.
- A target call has no time limit. An allowed agent user can occupy all 64 connection slots with slow effects, despite the 10-second frame deadline and 1 MiB frame cap.
- Expiry checks use the executor's clock and a five-second skew allowance in agent-warrant. The live run measured 1.5 to 11.3 ms per tool-server round trip on one laptop; no load or concurrency test exists.

### Detection and operator state

- Detection runs after the effect. The first unusual in-scope call can complete before an alert suspends the executor. The delegation-depth check is skipped.
- An alert-triggered revocation has no reason or actor in its ledger row. The routed-alert record keeps the event key, action and outcome; the signed audit log can reproduce the alert.
- An unreadable audit or routed-alert record stops automatic response until an operator repairs it ([Operations](OPERATIONS.md)). Alert actions have at-least-once delivery, so a crash before recording an action can cause it to run again.
- `routed.jsonl` is unsigned local state. A process able to write it as the operator's user can suppress or repeat a response. Delivery applies only to events within the scanned window.
- Alert-state and issuance-log locks use `flock` on a local filesystem. A shared network filesystem is not supported.

