# Risk mapping

A partial mapping of this reference implementation, with no compliance claim. Category names were checked against the sources below on 2026-11-08; their full requirements were not assessed.

Sources:

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) and its [announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/), used for category names only.
- [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf), used for the cited `MANAGE 2.4` outcome.

## OWASP Top 10 for Agentic Applications

| Id | Name | What this repository does | Not covered |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | limits what a hijacked agent can do (scope, budget, expiry); flags persona deviations after the fact (`demo/scenarios.py::persona_deviation`); a live model told to obey an injected document was refused ([LIVE_RUN.md](LIVE_RUN.md)) | preventing the hijack |
| ASI02 | Tool Misuse | scope match, cost cap and guard policy before every effect (`tests/test_executor.py::test_tool_outside_scope_is_refused`) | misuse inside granted scope and budget |
| ASI03 | Identity & Privilege Abuse | task-scoped authority narrowed per hop; the agent holds a signing key but no executor service credential (`demo/scenarios.py::budget_exhaustion`, `tests/test_enforced_process.py::test_stateless_agent_receives_no_executor_secret_and_still_gets_effect`) | agent attestation; key custody on the agent side |
| ASI07 | Insecure Inter-Agent Communication | delegation records are signed and hash-chained; agent-warrant verifies them, and rejecting an altered record is not tested here (`demo/scenarios.py::mid_chain_revocation` shows revocation only) | any transport or messaging between agents |
| ASI08 | Cascading Failures | budgets bound the blast radius; revoking a root stops all descendants (`demo/scenarios.py::root_revocation_cascade`) | failures of dependencies and tools |
| ASI10 | Rogue Agents | suspend and revoke levers; alert routing (`demo/scenarios.py::kill_levers`, `demo/scenarios.py::alert_stops_live_chain`) | detecting an agent that never passes the executor |

No control is claimed here for ASI04, ASI05, ASI06 or ASI09. The `require_human` verdict is refused because no approval flow is wired.

## NIST AI RMF 1.0

| Item | Text (abridged) | What this repository does | Not covered |
|---|---|---|---|
| MANAGE 2.4 | mechanisms to supersede, disengage or deactivate AI systems that show outcomes inconsistent with intended use | suspend and revoke levers with a named releaser (`demo/scenarios.py::kill_levers`) | deciding when to use them beyond the persona checks |

No mapping is claimed for the other AI RMF functions.
