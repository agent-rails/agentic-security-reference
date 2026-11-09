# Threat model

## Assumptions

- The agent is a steerable, untrusted insider. It may be compromised, may reason about the controls, and may send any bytes.
- The executor, the ledger file, the issuer key, the audit key and the target secrets are trusted. Compromise of the executor is total.
- Issuers are trusted only within the allowance the executor's trust policy gives them.

## Defended

Each row cites a test that exercises the defense under its fixture. Where the defense is only partly tested, the row says so.

| Threat | Defense | Test |
|---|---|---|
| Agent reads a secret or credential | secrets live in the executor process; the agent's argv, environment and responses contain none | `tests/test_enforced_process.py::test_agent_process_holds_no_secret_and_still_gets_its_effect`, `tests/test_enforced_process.py::test_response_never_carries_a_credential` |
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
| Repeating a request | the same nonce from the same holder is refused with the stored state, at any later time | `tests/test_executor.py::test_identical_request_is_not_performed_twice`, `tests/test_executor.py::test_identical_request_in_a_later_second_returns_the_stored_state` |
| Delegation outliving a revocation | revoking a root, link, task or tenant stops later requests | `demo/scenarios.py::root_revocation_cascade`, `demo/scenarios.py::mid_chain_revocation`, `tests/test_operator.py::test_revoking_a_task_or_a_tenant_stops_the_chain` |
| A copied credential used elsewhere | the target refuses another holder key, another operation, altered arguments, a reuse and an expired credential | `demo/scenarios.py::stolen_credential` |
| Fault between steps | after a restart from the state on disk, no second credential is minted for one operation; an unknown outcome is surfaced and its cost stays spent. The faults are raised inside the process; a killed process is not simulated | `demo/scenarios.py::crash_recovery` |
| Tampered evidence feeding the detector | the operator refuses to route any alert while a row fails verification or parsing | `tests/test_operator.py::test_tampered_audit_rows_are_not_trusted_by_the_detector` |
| One alert acting twice | each detected event is recorded once its action reaches a final outcome, so a rescan does not re-suspend after an authorized resume | `tests/test_operator.py::test_rescanning_the_same_log_after_resume_does_not_suspend_again` |

## Not defended, or defended only in part

- Binding of the credential is enforced only where the target verifies the executor proof and the operation digest. A target that accepts any bearer value gets no such protection. Such a target should receive a short-lived, narrow token held only by the executor; that path is not built here.
- Inventory: only agents whose effects pass the executor or a guard appear. No egress proxy is built, so an agent with network access can reach targets directly. Enforced mode therefore requires the agent to run with egress denied; this code does not set that up.
- Identity: an agent is a public key with no attestation. Evidence names it for attribution. The `host` field is a claim, recorded with the prefix `claim:`. A `trace_id` sent by the agent is carried into evidence for correlation and is also a claim; `call_id` is generated by the executor.
- Tenants: records carry `tenant_id`, and the ledger keys tasks by tenant. Evidence is one file; per-tenant partitioning and hosted multi-tenancy are not built.
- Evidence: HMAC with a shared key. A party without the key cannot forge or edit a record; a compromised producer can sign anything, and a producer that writes nothing leaves no gap to detect. Row MACs prove each row is unaltered, not that the log is complete: a deleted or truncated row is invisible to the detector. An external append-only sink is not built.
- Single ledger: revocation and budgets bind only executors that consult that ledger. A delegation presented elsewhere is not stopped. The ledger is a single SQLite file on one host; other hosts need a networked database behind the same interface.
- Same OS user: without `agent_uid` and `agent_gid`, the agent runs as the executor's user and can read the secrets and ledger, delete the suspension state, and roll back the ledger; that setup is not a custody boundary. Separate-user mode is tested on Linux in CI; on macOS only the same-user path of the peer check is tested. The operator runs as the executor's user.
- Issued credentials live until their ttl, 30 seconds in the demo configuration; suspension and revocation affect new ones.
- A revocation made from an alert is a ledger row with no reason or actor. The operator's record of routed alerts keeps only the event key, the action and its outcome; the alert itself can be derived again from the signed audit log.
- Detection is after the fact. The first in-scope but unusual call is performed before an alert can suspend anything. The delegation depth check is skipped.
- One ID token can be exchanged for several task roots until it expires, and the caller chooses each root's subject key: whoever holds a valid ID token, including a thief, can mint roots for a key of their choosing until the token expires. Roots never outlive the token.
- Issuer refusal messages carry the underlying reason, for example a JWKS fetch error. A service in front of the issuer should log them and return a generic refusal.
- Lost responses: if an agent loses the executor's answer and retries with a new nonce, the executor sees a new operation and the effect can run twice. A retry must reuse the nonce. It is then refused as in progress, or with the stored state (`already_done`, `already_outcome_unknown`), at any later time, and never runs again (`tests/test_executor.py::test_identical_request_is_not_performed_twice`, `tests/test_executor.py::test_identical_request_in_a_later_second_returns_the_stored_state`, `tests/test_executor.py::test_retry_after_an_unknown_outcome_reports_it_and_never_runs_again`, `tests/test_executor.py::test_replay_while_the_first_request_is_in_flight_leaves_the_first_one_alone`). A real target should also deduplicate on its own business key, because the executor cannot tell two nonces for the same intent apart.
- Denial of service: connections are capped at 64 and a frame must arrive within 10 seconds, but a target call has no time limit, so the allowed agent user can hold every slot with slow effects. Frames are capped at 1 MiB.
- Alert routing fails loud: one unreadable audit row, or an unreadable record of routed alerts, stops automatic response until an operator repairs it ([OPERATIONS.md](OPERATIONS.md)). Delivery is at least once: a crash between an action and its record re-applies the action on the next scan.
- After the ledger marks an operation issued, a failure returns `outcome_unknown` with the `op_id`, not a refusal. If the failure was writing evidence, the effect may have run with no terminal evidence row.
- `routed.jsonl`, the record of alerts already acted on, is unsigned local state: whoever can write it as the operator's user can suppress or repeat a response. Delivery is at least once only for events still inside the scanned window.
- Locks on the alert state and the issuance log are `flock` locks on a local filesystem; a network filesystem shared between hosts is not supported.
- Prompt injection itself, memory poisoning, code execution inside the agent, and supply-chain compromise of the agent's tooling are not addressed; the design limits what a compromised agent can do, not whether it is compromised.
- Time: expiry checks use the executor's clock and a 5 second skew allowance in agent-warrant.
- Performance: the live run measured 1.5 to 11 ms per executor call on one laptop. No load or concurrency test exists.

## Independent cross-check

On 2026-11-09, agent-warrant at `e2b4e24` was threat modelled with Grim Prompter (quick mode, agentic AI architecture, library revision `3642a31`), run read-only through a second model vendor. It modelled the library alone, without this executor, so it reports design hypotheses, not confirmed defects. Its report is private review material and is not part of this repository.

| Scenario it raised | Where this repository stands |
|---|---|
| A caller does not bind the scope check, the cost and the downstream operation to the same exact action | covered: the executor checks scope and a policy-owned cost, and binds the credential to the operation digest; the target checks the arguments against it |
| A lost response and a retry with a new operation id cause a second effect | stated limit: see lost responses above |
| A credential issued before a revocation is used after it | stated limit: an issued credential lives until its ttl |
| Unsigned roots naming a `did:web` issuer tie up verifier workers in name resolution before any signature is checked | not applicable here, because issuer keys are pinned in configuration; it applies to users of agent-warrant's `did:web` resolver, whose own threat model already discloses the name-resolution timeout |
| Code running as the executor's OS user alters the ledger | stated limit: same-user mode is not a custody boundary; separate-user mode is the answer |

