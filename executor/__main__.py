from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from .config import build_executor, load_config
from .server import ExecutorServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="executor", description="Run the effect executor on a Unix socket.")
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args(argv)
    built = build_executor(load_config(arguments.config))
    server = ExecutorServer(built.executor, built.run_dir, built.agent_uid)
    signal.signal(signal.SIGTERM, lambda *_: server.shutdown_from_signal())
    print(f"executor listening on {server.socket_path}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if os.path.lexists(server.socket_path):
            os.unlink(server.socket_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
