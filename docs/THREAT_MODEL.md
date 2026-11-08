# Threat model

## Assumptions

- The agent is a steerable, untrusted insider. It may be compromised, may reason about the controls, and may send any bytes.
- The executor, the ledger file, the issuer key, the audit key and the target secrets are trusted. Compromise of the executor is total.
- Issuers are trusted only within the allowance the executor's trust policy gives them.

## Defended

Each line names a test that fails if the behaviour is removed.

| Threat | Defence | Test |
|---|---|---|
| Agent reads a secret or credential | secrets live in the executor process; the agent's argv, environment and responses contain none | `tests/test_enforced_process.py::test_agent_process_holds_no_secret_and_still_gets_its_effect`, `tests/test_enforced_process.py::test_response_never_carries_a_credential` |
| Agent claims an identity, tenant or cost | the strict decoder refuses unknown fields; identity comes from the verified chain; cost comes from a policy-owned schedule | `tests/test_evidence_identity.py::test_identity_fields_supplied_by_the_agent_are_refused_and_never_recorded`, `tests/test_executor.py::test_agent_cannot_state_its_own_cost` |
| Agent chooses or collides an operation id | the wire request has no `op_id`; the executor derives it | `tests/test_executor.py::test_wire_request_has_no_op_id_field` |
| Request altered after the agent signed its proof | the leaf proof binds the request digest and the executor's audience | `tests/test_executor.py::test_proof_for_another_request_is_refused`, `tests/test_executor.py::test_proof_addressed_to_another_verifier_is_refused` |
| Validly signed root from an issuer that may not assert it | executor trust policy: listed issuer, tenant, principal, budget | `demo/scenarios.py::rogue_issuer` |
| Forged or mis-claimed ID token | signature, issuer, audience, expiry, not-before and required claims are checked; algorithm allowlist; claims-to-tenant mapping; ceilings per tenant | `tests/test_issuer.py` |
| Spending past a budget | link caps and the task pool are reserved in one ledger transaction | `demo/scenarios.py::budget_exhaustion` |
| Repeating a request | the same nonce from the same holder is refused as already done | `tests/test_executor.py::test_identical_request_is_not_performed_twice` |
| Delegation outliving a revocation | revoking a root, link, task or tenant stops later requests | `demo/scenarios.py::root_revocation_cascade`, `demo/scenarios.py::mid_chain_revocation`, `tests/test_operator.py` |
| A copied credential used elsewhere | the target refuses another holder key, another operation, altered arguments, a reuse and an expired credential | `demo/scenarios.py::stolen_credential` |
| Crash between steps | no second credential is minted for one operation; an unknown outcome is surfaced and its cost stays spent | `demo/scenarios.py::crash_recovery` |
| Tampered evidence feeding the detector | rows whose signature does not verify are excluded | `tests/test_operator.py::test_tampered_audit_rows_are_not_trusted_by_the_detector` |

## Not defended, or defended only in part

- Binding of the credential is enforced only where the target verifies the executor proof and the operation digest. A target that accepts any bearer value gets no such protection. The fallback is a short-lived, narrow token held only by the executor.
- H3, inventory: only agents whose effects pass the executor or a guard appear. No egress proxy is built, so an agent with network access can reach targets directly. Enforced mode therefore requires the agent to run with egress denied; this code does not set that up.
- H4, identity: an agent is a public key with no attestation. Evidence names it for attribution. The `host` field is a claim, recorded with the prefix `claim:`.
- M7, tenants: records carry `tenant_id`, and the ledger keys tasks by tenant. Evidence is one file; per-tenant partitioning and hosted multi-tenancy are not built.
- M8, evidence: HMAC with a shared key. A party without the key cannot forge or edit a record; a compromised producer can sign anything, and a producer that writes nothing leaves no gap to detect. An external append-only sink is not built.
- Single ledger: revocation and budgets bind only executors that consult that ledger. A delegation presented elsewhere is not stopped. The ledger is a single SQLite file on one host; other hosts need a networked database behind the same interface.
- Same OS user: code running as the executor's user can read the secrets and ledger, delete the suspension state, and roll back the ledger. Separating users is the intent of enforced mode and is not tested on macOS. The socket is mode 0600 in a 0700 directory, which also keeps a differently privileged agent user out; connecting from another user needs a deliberate permission change.
- Issued credentials live until their ttl; suspension and revocation affect new ones.
- Detection is after the fact. The first in-scope but unusual call is performed before an alert can suspend anything. The delegation depth check is skipped.
- One ID token can be exchanged for several task roots until it expires.
- Denial of service: the server starts a thread per connection with no connection limit; frames are capped at 1 MiB.
- Prompt injection itself, memory poisoning, code execution inside the agent, and supply-chain compromise of the agent's tooling are not addressed; the design limits what a compromised agent can do, not whether it is compromised.
- Time: expiry checks use the executor's clock and a 5 second skew allowance in agent-warrant.
- Performance is not measured here.
