from __future__ import annotations

import socket
import struct
import sys

LINUX_UCRED = struct.Struct("=iII")
DARWIN_SOL_LOCAL = 0
DARWIN_LOCAL_PEERCRED = 1
DARWIN_XUCRED = struct.Struct("=IIh2x16I")


def check_supported() -> None:
    if sys.platform not in ("linux", "darwin"):
        raise RuntimeError(f"peer credential check is not implemented on {sys.platform}")


def peer_uid(connection: socket.socket) -> int:
    """The user id of the process on the other end of a Unix socket, as the kernel recorded it at connect."""
    if sys.platform == "linux":
        data = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, LINUX_UCRED.size)
        return int(LINUX_UCRED.unpack(data)[1])
    if sys.platform == "darwin":
        data = connection.getsockopt(DARWIN_SOL_LOCAL, DARWIN_LOCAL_PEERCRED, DARWIN_XUCRED.size)
        return int(DARWIN_XUCRED.unpack(data)[1])
    raise RuntimeError(f"peer credential check is not implemented on {sys.platform}")
