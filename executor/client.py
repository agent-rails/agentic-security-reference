from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from typing import Any

from .protocol import Request, encode_request, read_frame, write_frame


def send_frame(socket_path: Path, frame: bytes, timeout: float = 30.0) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(socket_path))
        write_frame(connection, frame)
        response: dict[str, Any] = json.loads(read_frame(connection, time.monotonic() + timeout))
        return response


def send_request(socket_path: Path, request: Request, timeout: float = 30.0) -> dict[str, Any]:
    return send_frame(socket_path, encode_request(request), timeout)
