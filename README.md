# agentic-security-reference

A reference architecture and runnable demo for agentic security. It treats an agent as a steerable, untrusted insider, so authority is a task and a chain of delegations rather than a standing role, and every effect is checked where it happens.

The code here is glue plus a demo. The primitives live in two libraries, pinned to commit SHAs in `pyproject.toml`: [agent-warrant](https://github.com/agent-rails/agent-warrant) (signed task roots, delegation chains, the budget and revocation ledger) and [agent-guard](https://github.com/agent-rails/agent-guard) (policy decision, credential injector, evidence, detection).

## Motivation

Two public posts, both the companies' own reports:

- Uber, [Securing AI agents](https://www.uber.com/us/en/blog/securing-ai-agents/): a registry, a decision service, enforcement in an SDK, declared versus observed capability, one trace, and replay before enforcing. It publishes no numbers.
- Binance, initial report of 29 October 2026 (the mechanism of the AI-tool misuse was not disclosed): a long-lived deploy token on a laptop used from another engineer's machine, a signing service that accepted requests outside the normal process, five hot wallets drained in about four minutes and caught by a volume alert, and on-chain delegations that outlived the shutdown. Scenario 5 reproduces one of these patterns, a copied credential presented elsewhere. It makes no claim about Binance's systems.

## Thesis

- An agent is steerable by what it reads. It must not hold standing credentials or decide its own authority.
- The unit of authority is a task: a signed task root issued for a human, narrowed at every delegation hop, with a budget and an expiry.
- The check sits at the effect, in a process the agent cannot reach, and fails closed.
- Evidence for a verified request carries identity taken from the chain, never from the request.
- Stopping has two independent levers: refuse new credentials (effect stop) and revoke chains (authority stop).

## Layers

Built means exercised by a test in this repository. The evidence for each row is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#layer-coverage).

| Layer | Status |
|---|---|
| Human request | built, with limits |
| Issuer | built, with limits |
| Task root | built |
| Delegation | built |
| Agent | stated limit |
| Decision | built, with limits |
| Credential | built, enforced only where the target verifies it |
| Effect | fake targets only |
| Evidence | built, with limits |
| Detection | built, off the request path |
| Stop | built, with limits |

## Modes

| Mode | What it is | Custody claim |
|---|---|---|
| Advisory | agent-guard in the agent's process | none: records and steers; same-user code can bypass or roll back state |
| Enforced | the executor in its own process holds all secrets and performs effects | the agent process holds no secret; egress is not restricted because no egress proxy is built, so the agent must run with egress denied |
| Isolated | enforced plus a sandbox (VM or container) around the agent | not built |

## Adoption paths

| You have | Use | You get |
|---|---|---|
| Only a tool-call hook | agent-guard alone | policy decision, audit, advisory mode |
| Only services that must accept delegated authority | agent-warrant alone | `verify_chain` in your service, plus the ledger for revocation and budgets |
| An agent that must not hold credentials | both, through the executor in this repository | enforced mode as demonstrated here |

## Records and signing

The reader surface is four records: `TaskRoot`, `ChainLink`, `LeafProof` and `Operation`. agent-warrant's v1 `Grant` and `RevocationList` are legacy and are not used here.

| Scheme | Used for | Key holder |
|---|---|---|
| Ed25519 | `TaskRoot` (issuer key), `ChainLink` (parent holder key), `LeafProof` (leaf holder key), the executor's proof over a credential (executor key) | each signer; verifiable without sharing a secret |
| HMAC-SHA256 | audit records (audit key), alerts (alert key), the credential MAC (the target's secret) | shared between signer and verifier |

## MCP

No MCP client is built here. The design fit: the executor would be the MCP client and hold the credentials, obtain a separate token per MCP server audience, and never forward a task grant or any token it received. The MCP authorization specification requires a server not to accept or pass through tokens issued for other audiences (as read on 2026-11-07, version 2026-07-28).

## Quickstart

Install, lint, type-check and test (the same commands CI runs):

```sh ci
python -m pip install -e ".[dev]"
ruff check
ruff format --check
mypy
pytest -q
```

Run the eleven scenarios, each printing what happened and asserting it:

```sh runnable
python -m demo
```

A scenario is an ordinary function. This one is copied from the test suite and builds a world, a task root and a request:

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

## Repository map

| Path | Contents |
|---|---|
| `executor/` | the effect executor: protocol, core, server, operator, credentials, targets |
| `issuer/` | OIDC task-root issuer |
| `demo/` | scenarios and the world they run in |
| `tests/` | unit and integration tests; the scenarios run as tests |
| `docs/` | architecture, threat model, decisions, risk mapping |

Every fenced `sh` or `python` block in the docs is either run by `tests/test_docs_commands.py` or is a command that `.github/workflows/ci.yml` runs.
