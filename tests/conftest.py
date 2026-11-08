import pytest

from demo.agents import Agent
from demo.world import World


@pytest.fixture
def world():
    world = World()
    yield world
    world.stop()


@pytest.fixture
def running(world):
    return world.start_in_process()


@pytest.fixture
def alice(world):
    agent = Agent("alice")
    world.root_for(agent)
    return agent
