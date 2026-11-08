from __future__ import annotations

import sys

from .scenarios import SCENARIOS
from .story import ScenarioFailed, Story


def main() -> int:
    failures = 0
    for number, title, scenario in SCENARIOS:
        print(f"\nScenario {number}: {title}")
        try:
            scenario(Story(title, emit=print))
        except ScenarioFailed:
            failures += 1
    print(f"\n{len(SCENARIOS) - failures} of {len(SCENARIOS)} scenarios passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
