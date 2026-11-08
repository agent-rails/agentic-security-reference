from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
import sys
import threading
import time
import traceback
from pathlib import Path

from .core import Executor
from .peer import check_supported, peer_uid
from .protocol import ProtocolError, read_frame, write_frame

SOCKET_NAME = "executor.sock"
FRAME_DEADLINE_SECONDS = 10.0
MAX_CONNECTIONS = 64


def prepare_run_dir(run_dir: Path, mode: int = 0o700, group: int | None = None) -> Path:
    """The directory holding the socket must be a real directory owned by this user with `mode` (and `group`,
    when given), reached by an absolute path with no symlink in it, and no directory above it may be owned by
    another user or writable by others unless it is sticky, so no other user can rename or swap it between the
    check and the bind."""
    if not run_dir.is_absolute() or os.path.realpath(run_dir) != str(run_dir):
        raise ValueError(f"run_dir must be an absolute path with no symlink in it: {run_dir}")
    run_dir.mkdir(mode=mode, parents=True, exist_ok=True)
    if os.path.realpath(run_dir) != str(run_dir):
        raise ValueError(f"run_dir must be an absolute path with no symlink in it: {run_dir}")
    if group is not None:
        os.chown(run_dir, -1, group, follow_symlinks=False)
    for ancestor in run_dir.parents:
        above = os.stat(ancestor)
        shared = above.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not above.st_mode & stat.S_ISVTX
        if above.st_uid not in (0, os.geteuid()) or shared:
            raise ValueError(f"run_dir has an ancestor owned or writable by another user: {ancestor}")
    info = os.lstat(run_dir)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != mode
        or (group is not None and info.st_gid != group)
    ):
        raise ValueError(f"run_dir must be a real directory owned by this user with mode {mode:04o}: {run_dir}")
    return run_dir


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        connection: socket.socket = self.request
        try:
            frame = read_frame(connection, time.monotonic() + FRAME_DEADLINE_SECONDS)
        except (ProtocolError, OSError):
            return
        response = self.server.executor.handle(frame)
        try:
            connection.settimeout(FRAME_DEADLINE_SECONDS)
            write_frame(connection, json.dumps(response).encode())
        except OSError:
            traceback.print_exc(file=sys.stderr)


class ExecutorServer(socketserver.ThreadingUnixStreamServer):
    """Serves the executor on a Unix socket and accepts a connection only from one user id, checked against the
    kernel's peer credentials. With no `agent_uid` that is this user, which gives no custody boundary: an agent
    running as the executor's user can read its secrets. With `agent_uid` the agent runs as that other, non-root
    user, and the directory and socket are opened to `agent_gid` only, a group the executor belongs to, so other
    users cannot reach the socket at all."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self, executor: Executor, run_dir: Path, agent_uid: int | None = None, agent_gid: int | None = None
    ) -> None:
        check_supported()
        if agent_uid is None and agent_gid is not None:
            raise ValueError("agent_gid is set without agent_uid")
        if agent_uid is not None:
            if agent_uid in (0, os.geteuid()):
                raise ValueError("agent_uid must be a non-root user other than the executor's")
            if agent_gid is None or agent_gid == 0 or agent_gid not in {os.getegid(), *os.getgroups()}:
                raise ValueError("agent_gid must be a non-root group the executor belongs to")
        self.executor = executor
        self.allowed_uid = os.geteuid() if agent_uid is None else agent_uid
        run_mode, socket_mode = (0o700, 0o600) if agent_uid is None else (0o710, 0o660)
        self.socket_path = prepare_run_dir(run_dir, run_mode, agent_gid) / SOCKET_NAME
        if os.path.lexists(self.socket_path):
            raise ValueError(f"socket path already exists: {self.socket_path}")
        previous = os.umask(0o177)
        try:
            super().__init__(str(self.socket_path), _Handler)
        finally:
            os.umask(previous)
        if agent_gid is not None:
            os.chown(self.socket_path, -1, agent_gid, follow_symlinks=False)
        os.chmod(self.socket_path, socket_mode)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._thread: threading.Thread | None = None

    def process_request(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        if peer_uid(request) != self.allowed_uid or not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:  # type: ignore[override]
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

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
