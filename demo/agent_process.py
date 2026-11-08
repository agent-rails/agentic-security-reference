from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from executor.client import send_frame


def main() -> int:
    """An agent in its own process. It reads prepared request frames from stdin, sends them to the executor
    socket named in argv, and prints the responses with its own argv and environment so a caller can inspect
    what the agent process holds."""
    socket_path = Path(sys.argv[1])
    frames = json.load(sys.stdin)
    responses = [send_frame(socket_path, frame.encode()) for frame in frames]
    print(json.dumps({"responses": responses, "argv": sys.argv, "env": dict(os.environ)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
