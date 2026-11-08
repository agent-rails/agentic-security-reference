import pytest

from demo.scenarios import SCENARIOS
from demo.story import Story


@pytest.mark.parametrize(("number", "title", "scenario"), SCENARIOS, ids=[f"{n}-{t}" for n, t, _ in SCENARIOS])
def test_scenario(number, title, scenario):
    story = Story(title)
    scenario(story)
    assert story.lines
    assert not any("FAIL" in line for line in story.lines)
