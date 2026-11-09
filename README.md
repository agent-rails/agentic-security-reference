# agentic-security-reference

A runnable reference for giving AI agents task-scoped authority without giving them downstream service credentials.

An agent can be steered by what it reads, so this design treats it as an untrusted insider. The agent holds its own signing key and a task-scoped delegation chain, but no downstream service credential. A separate executor checks each action before performing it and records evidence.

## Try it

Use Python 3.13.

```sh ci
python -m pip install --require-hashes -r requirements-ci.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m pip check
ruff check
ruff format --check
mypy
pytest -q
```

Run the eleven scenarios. Each prints what happened and checks it:

```sh runnable
python -m demo
```

The last line should read `11 of 11 scenarios passed`.

## Tested with a real model

The scenarios script the agent. In the [live run](docs/LIVE_RUN.md), Claude chose its own actions across five scenarios, each repeated three times. Under an instruction to follow every step in a release document, it attempted an out-of-scope withdrawal in all three runs. The executor refused each attempt.

The tool server held the agent's signing key, while executor service credentials stayed out of tool responses. The run used fake targets and one OS user, so it did not establish filesystem custody between the agent and executor. The [results and limits](docs/LIVE_RUN.md) record the other scenarios, timings and environment exposure.

## What the demo shows

| # | Scenario | What it checks |
|---|---|---|
| 1 | happy path | a human's task reaches an effect through one delegation hop |
| 2 | budget exhaustion | a task's budget holds across every hop |
| 3 | root revocation | revoking a task stops every agent below it |
| 4 | mid-chain revocation | revoking one link stops only that subtree |
| 5 | stolen credential | a copied credential fails at the target |
| 6 | rogue issuer | a validly signed task from an untrusted issuer is refused |
| 7 | kill levers | stop new effects, or stop authority, independently |
| 8 | crash recovery | a fault between steps never issues a second credential |
| 9 | enforced mode | a stateless agent process receives no executor secret and still gets its effect |
| 10 | persona deviation | an unusual in-scope action is flagged and the executor suspended |
| 11 | alert stops a chain | an alert revokes a live delegation chain mid-task |

## How it works

```mermaid
flowchart LR
    H[Human] -->|ID token| I[Issuer]
    I -->|signed task root| A[Agent]
    A -->|narrower delegation| S[Sub-agent]
    S -->|request + proof| X[Executor]
    X -->|check, reserve, credential| T[Target]
    X -->|signed evidence| E[(Audit log)]
    E --> O[Operator]
```

1. **A human starts a task.** The issuer verifies their OIDC ID token and signs a task root containing the principal, purpose, scope, budget and expiry.
2. **Agents delegate.** Each hop signs a narrower link. Scope and budget can only shrink.
3. **The executor checks every action.** It runs in its own process and holds the target credential material and its own signing and audit keys. It verifies the chain, scope, cost and policy, and reserves budget in the ledger.
4. **It performs the effect.** It mints a short-lived credential bound to that one operation. The fake target's response contains no credential; a real integration must restrict target responses before forwarding them to an agent.
5. **It records evidence, and the operator can stop things.** Identity comes from the verified chain, never from the request. The operator suspends new credentials or revokes authority, by hand or from alerts.

The [architecture](docs/ARCHITECTURE.md) traces the full request path.

## What is protected

| Mode | What it is | What you can claim |
|---|---|---|
| Advisory | agent-guard inside the agent's process | records and steers; not a security boundary |
| Enforced | the executor holds downstream credential material in its own process | the agent holds its signing key; fake targets return no executor credential |
| Isolated | enforced, plus a VM or container around the agent | not built |

Real target adapters must restrict responses and errors before returning them to an agent. For filesystem separation, run the agent under a distinct OS user with `agent_uid` and `agent_gid`; Linux CI tests this mode. The same-user mode does not protect executor files from the agent.

This reference does not cover the following.

- **Egress:** no egress proxy is built, so in enforced mode the agent must run with network egress denied.
- **Real targets:** the targets are fakes that verify the credential binding; a real target that accepts any bearer token gets weaker protection.
- **Detection:** it runs after the fact, so a flagged action has already happened.
- **Scale:** the ledger is one SQLite file on one host.
- **Prompt injection itself:** this limits what a compromised agent can do, not whether it is compromised.

The [threat model](docs/THREAT_MODEL.md) ties each claimed defense to a test.

## Use it

The code here is glue plus a demo. The primitives live in two libraries, pinned to exact PyPI releases in `pyproject.toml`:

- [agent-warrant](https://github.com/agent-rails/agent-warrant) provides signed task roots, delegation chains, and the budget and revocation ledger.
- [agent-guard](https://github.com/agent-rails/agent-guard), published on PyPI as `toolcall-authz`, provides policy decisions, the credential injector, evidence and detection.

| You have | Use | You get |
|---|---|---|
| Only a tool-call hook | agent-guard alone | policy decisions and audit, advisory mode |
| Services that must accept delegated authority | agent-warrant alone | `verify_chain` in your service, plus the ledger for revocation and budgets |
| An agent that must not hold downstream service credentials | both, through the executor here | enforced mode as demonstrated |

A scenario is an ordinary function. This one builds a world, issues a task root and sends a request:

```python runnable
from demo.agents import Agent
from demo.world import World

world = World()
try:
    world.start_in_process()
    agent = Agent("release-bot")
    world.root_for(agent)
    response = world.send(agent, "deploy.service", "env/staging/api", {"image": "api:1"}, "n1")
    assert response["status"] == "done", response
finally:
    world.stop()
```

## Why

Three failure patterns recur once agents get real access.

- **A copied token works anywhere.** A long-lived token on one machine is used from another. Here each credential is bound to one operation and the executor's key, and expires 30 seconds after issue in the demo configuration; a copy fails at the target (scenario 5).
- **A side door skips the checks.** A service accepts a request that did not go through the normal process. In this demo, every effect passes the executor, and the fake targets accept only credentials it injected (scenarios 1 and 5).
- **Authority outlives the decision to stop.** Delegations keep working after the shutdown. Here revoking a task, a link or a tenant stops every chain below it on the next request (scenarios 3, 4, 7 and 11).

## Documentation

| Document | Read it for |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the request path, layer coverage, records and signing, MCP fit |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | what is defended, with tests, and what is not |
| [docs/DECISIONS.md](docs/DECISIONS.md) | why it is built this way |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | what to do when something refuses to continue |
| [docs/LIVE_RUN.md](docs/LIVE_RUN.md) | a real model driving the agent, and what it showed |
| [docs/RISK_MAPPING.md](docs/RISK_MAPPING.md) | a partial mapping to OWASP and NIST names |

## License

Apache-2.0.
