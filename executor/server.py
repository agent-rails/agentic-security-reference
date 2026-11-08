from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
import sys
import threading
import traceback
from pathlib import Path

from .core import Executor
from .protocol import ProtocolError, read_frame, write_frame

SOCKET_NAME = "executor.sock"
CONNECTION_TIMEOUT_SECONDS = 10.0


def prepare_run_dir(run_dir: Path) -> Path:
    """The directory holding the socket must be a real directory owned by this user with mode 0700."""
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(run_dir)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"run_dir must be a real directory owned by this user with mode 0700: {run_dir}")
    return run_dir


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection: socket.socket = self.request
        connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
        try:
            frame = read_frame(connection)
        except (ProtocolError, OSError):
            return
        response = self.server.executor.handle(frame)
        try:
            write_frame(connection, json.dumps(response).encode())
        except OSError:
            traceback.print_exc(file=sys.stderr)


class ExecutorServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, executor: Executor, run_dir: Path) -> None:
        self.executor = executor
        self.socket_path = prepare_run_dir(run_dir) / SOCKET_NAME
        if os.path.lexists(self.socket_path):
            raise ValueError(f"socket path already exists: {self.socket_path}")
        previous = os.umask(0o177)
        try:
            super().__init__(str(self.socket_path), _Handler)
        finally:
            os.umask(previous)
        os.chmod(self.socket_path, 0o600)
        self._thread: threading.Thread | None = None

    def start_in_background(self) -> None:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
        if os.path.lexists(self.socket_path):
            os.unlink(self.socket_path)

    def shutdown_from_signal(self) -> None:
        threading.Thread(target=self.shutdown).start()
