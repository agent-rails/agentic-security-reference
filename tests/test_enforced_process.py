import json
import os
import stat
import subprocess
import sys
import time

import pytest

from demo.agents import Agent
from demo.world import EXECUTOR_ID, World
from executor.protocol import encode_request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def process_world():
    world = World(clock=time.time)
    world.start_process()
    yield world
    world.stop()


def run_agent_process(world, frames):
    environment = {"PATH": os.environ["PATH"]}
    argv = [sys.executable, "-m", "demo.agent_process", str(world.running.socket_path)]
    result = subprocess.run(
        argv, input=json.dumps(frames), capture_output=True, text=True, env=environment, cwd=REPO, timeout=60
    )
    assert result.returncode == 0, result.stderr
    return result.stdout, argv, environment


def test_agent_process_holds_no_secret_and_still_gets_its_effect(process_world, monkeypatch):
    world = process_world
    for name, value in world.secrets.items():
        monkeypatch.setenv(f"{name.upper().replace('-', '_')}_SECRET", value.decode())
    agent = Agent("alice")
    world.root_for(agent)
    request = agent.request(
        audience=EXECUTOR_ID,
        now=world.now,
        tool="deploy.service",
        resource="env/staging/api",
        args={"image": "api:1"},
        nonce="n1",
    )
    output, argv, environment = run_agent_process(world, [encode_request(request).decode()])
    report = json.loads(output)
    assert report["responses"][0]["status"] == "done"
    assert len(world.effects("deploy-api")) == 1
    secrets = [value.decode() for value in world.secrets.values()] + [world.audit_key.hex()]
    for secret in secrets:
        assert secret not in output
        assert not any(secret in argument for argument in report["argv"])
        assert not any(secret in value for value in report["env"].values())
        assert not any(secret in argument for argument in argv)
        assert not any(secret in value for value in environment.values())
    assert set(report["env"]) <= {"PATH", "LC_CTYPE", "__CF_USER_TEXT_ENCODING"}


def test_response_never_carries_a_credential(process_world):
    world = process_world
    agent = Agent("alice")
    world.root_for(agent)
    response = world.send(agent, "deploy.service", "env/staging/api", {}, "n1")
    assert response["status"] == "done"
    assert set(response) <= {"status", "reason", "op_id", "trace_id", "state", "result", "detail"}
    assert "mac" not in json.dumps(response)


def test_secret_files_and_state_are_private_to_the_executor_user(process_world):
    world = process_world
    for path in (world.exec_dir / "secrets").iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((world.exec_dir / "secrets").stat().st_mode) == 0o700
    assert stat.S_IMODE(world.ledger_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(world.running.socket_path.stat().st_mode) == 0o600
