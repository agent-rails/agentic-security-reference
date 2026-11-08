import grp
import json
import os
import pwd
import subprocess
import time

import pytest

from demo.agents import Agent
from demo.world import EXECUTOR_ID, World
from executor.client import send_frame
from executor.protocol import ProtocolError, encode_request

AGENT_USER = os.environ.get("ASR_AGENT_USER")
AGENT_GROUP = os.environ.get("ASR_AGENT_GROUP")

pytestmark = pytest.mark.skipif(
    not (AGENT_USER and AGENT_GROUP),
    reason="needs ASR_AGENT_USER, a second OS user reachable by sudo -n, and ASR_AGENT_GROUP, a group both share",
)

AGENT_CODE = """
import json, socket, struct, sys
socket_path, *private = sys.argv[1:]
denied = []
for path in private:
    try:
        open(path, "rb").read()
    except PermissionError:
        denied.append(path)
frame = sys.stdin.buffer.read()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(30)
    connection.connect(socket_path)
    connection.sendall(struct.pack(">I", len(frame)) + frame)
    header = connection.recv(4, socket.MSG_WAITALL)
    body = connection.recv(struct.unpack(">I", header)[0], socket.MSG_WAITALL)
print(json.dumps({"denied": denied, "response": json.loads(body)}))
"""


@pytest.fixture
def separate_world():
    world = World(
        clock=time.time, agent_uid=pwd.getpwnam(AGENT_USER).pw_uid, agent_gid=grp.getgrnam(AGENT_GROUP).gr_gid
    )
    world.start_process()
    yield world
    world.stop()


def test_agent_running_as_another_user_cannot_read_secrets_but_gets_its_effect(separate_world):
    world = separate_world
    agent = Agent("alice")
    world.root_for(agent)
    request = agent.request(
        audience=EXECUTOR_ID, now=world.now, tool="deploy.service", resource="env/staging/api", args={}, nonce="n1"
    )
    private = sorted(str(path) for path in world.exec_dir.rglob("*") if path.is_file() and not path.is_socket())
    assert {"config.json", "executor.key", "audit.key", "ledger.db", "deploy-api"} <= {
        os.path.basename(path) for path in private
    }
    result = subprocess.run(
        ["sudo", "-n", "-u", AGENT_USER, "/usr/bin/python3", "-I", "-c", AGENT_CODE, str(world.running.socket_path)]
        + private,
        input=encode_request(request),
        capture_output=True,
        cwd="/",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert sorted(report["denied"]) == sorted(private)
    assert report["response"]["status"] == "done"
    assert len(world.effects("deploy-api")) == 1


def test_executor_user_is_not_an_allowed_peer_in_separate_user_mode(separate_world):
    with pytest.raises((ProtocolError, OSError)):
        send_frame(separate_world.running.socket_path, b"{}")


CONNECT_CODE = """
import socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    try:
        connection.connect(sys.argv[1])
    except PermissionError:
        print("denied")
    else:
        print("connected")
"""


def test_user_outside_the_agent_group_cannot_reach_the_socket(separate_world):
    result = subprocess.run(
        [
            "sudo",
            "-n",
            "-u",
            "nobody",
            "/usr/bin/python3",
            "-I",
            "-c",
            CONNECT_CODE,
            str(separate_world.running.socket_path),
        ],
        capture_output=True,
        text=True,
        cwd="/",
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "denied"
