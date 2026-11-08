from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_warrant.canonical import MAX_SAFE_INTEGER


class CostError(Exception):
    pass


@dataclass(frozen=True)
class CostSchedule:
    """Policy-owned, versioned map from tool to cost. The agent never states a cost. A tool maps to a fixed
    integer or to the name of an integer argument (for example a withdrawal amount). A tool not listed has no
    cost and is refused."""

    version: int
    tools: Mapping[str, int | str]

    def cost(self, tool: str, args: dict[str, Any]) -> int:
        if tool not in self.tools:
            raise CostError(f"tool {tool!r} is not in cost schedule v{self.version}")
        rule = self.tools[tool]
        if isinstance(rule, int):
            return rule
        value = args.get(rule)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
            raise CostError(f"argument {rule!r} must be a non-negative integer to price {tool!r}")
        return value
