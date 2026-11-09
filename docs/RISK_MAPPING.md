# Risk mapping

A partial mapping, not a compliance claim. Names were read from the sources below on 2026-11-08. Anything not listed here was not verified and is omitted.

Sources:

- OWASP GenAI Security Project, Top 10 for Agentic Applications for 2026: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>. The ten names come from the project's announcement post: <https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/>. The full document is behind a download page that returned "No Access", so only the names were verified, not the descriptions.
- NIST AI RMF 1.0, NIST AI 100-1: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf>. NIST's page notes the framework is being revised.

## OWASP Top 10 for Agentic Applications

| Id | Name | What this repository does | Not covered |
|---|---|---|---|
| ASI01 | Agent Goal Hijack | limits what a hijacked agent can do (scope, budget, expiry); flags persona deviations after the fact (`demo/scenarios.py::persona_deviation`); a live model told to obey an injected document was refused ([LIVE_RUN.md](LIVE_RUN.md)) | preventing the hijack |
| ASI02 | Tool Misuse | scope match, cost cap and guard policy before every effect (`tests/test_executor.py::test_tool_outside_scope_is_refused`) | misuse inside granted scope and budget |
| ASI03 | Identity & Privilege Abuse | task-scoped authority narrowed per hop; the agent holds no secret (`demo/scenarios.py::budget_exhaustion`, `tests/test_enforced_process.py::test_agent_process_holds_no_secret_and_still_gets_its_effect`) | agent attestation; key custody on the agent side |
| ASI04 | Agentic Supply Chain Vulnerabilities | nothing | all of it |
| ASI05 | Unexpected Code Execution | nothing; isolated mode is not built | all of it |
| ASI06 | Memory & Context Poisoning | nothing | all of it |
| ASI07 | Insecure Inter-Agent Communication | delegation records are signed and hash-chained; agent-warrant verifies them, and rejecting an altered record is not tested here (`demo/scenarios.py::mid_chain_revocation` shows revocation only) | any transport or messaging between agents |
| ASI08 | Cascading Failures | budgets bound the blast radius; revoking a root stops all descendants (`demo/scenarios.py::root_revocation_cascade`) | failures of dependencies and tools |
| ASI09 | Human-Agent Trust Exploitation | nothing; `require_human` verdicts are refused, no approval flow is wired | all of it |
| ASI10 | Rogue Agents | suspend and revoke levers; alert routing (`demo/scenarios.py::kill_levers`, `demo/scenarios.py::alert_stops_live_chain`) | detecting an agent that never passes the executor |

## NIST AI RMF 1.0

| Item | Text (abridged) | What this repository does | Not covered |
|---|---|---|---|
| MANAGE 2.4 | mechanisms to supersede, disengage or deactivate AI systems that show outcomes inconsistent with intended use | suspend and revoke levers with a named releaser (`demo/scenarios.py::kill_levers`) | deciding when to use them beyond the persona checks |
| GOVERN, MAP, MEASURE | the other three functions | nothing mapped | all of it |
