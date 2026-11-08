from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from .agents import Agent
from .world import World


class ScenarioFailed(AssertionError):
    pass


class Story:
    """What a scenario prints. `expect` records an observed value and fails the scenario if it differs from the
    expected one, so the narrative and the check are the same statement."""

    def __init__(self, title: str, emit: Callable[[str], None] | None = None) -> None:
        self.title = title
        self.lines: list[str] = []
        self._emit = emit
        self._names: dict[str, str] = {}

    def _write(self, line: str) -> None:
        self.lines.append(line)
        if self._emit is not None:
            self._emit(line)

    def say(self, text: str) -> None:
        self._write(f"  {text}")

    def name(self, agent: Agent, label: str) -> Agent:
        self._names[agent.public_key] = label
        return agent

    def who(self, key: str) -> str:
        return self._names.get(key, key[:10])

    def expect(self, label: str, actual: Any, expected: Any) -> None:
        if actual != expected:
            self._write(f"  FAIL {label}: expected {expected!r}, observed {actual!r}")
            raise ScenarioFailed(f"{self.title}: {label}: expected {expected!r}, observed {actual!r}")
        self._write(f"  ok   {label}: {actual!r}")

    def outcome(self, label: str, response: dict[str, Any], status: str, reason: str | None = None) -> None:
        shown = response["status"] + (f" ({response['reason']})" if response["status"] != "done" else "")
        self.expect(label, shown, status + (f" ({reason})" if reason else ""))

    @contextmanager
    def world(self, *, real_time: bool = False) -> Iterator[World]:
        world = World(clock=time.time) if real_time else World()
        try:
            yield world
        finally:
            world.stop()
