"""The shell's own network namespace: loopback only, and on it the one socket the proxy serves.

Landlock's network rules name ports, not addresses: a shell allowed to connect to the proxy's port
could connect to that port on any host, and so skip the proxy (security review 2, SR-28). Inside an
empty namespace there is no other host to reach; the proxy, outside it, accepts on a socket made
inside it. Called in the forked child before the uid drops; root unshares the network namespace
directly, anyone else needs a user namespace around it. Where neither can be made, the shell is
refused: the host allowlist could not be held."""
import ctypes
import fcntl
import os
import socket
import struct

from sharness_ai import landlock
from sharness_ai.run import CLONE_NEWNET, CLONE_NEWUSER

SIOCGIFFLAGS, SIOCSIFFLAGS, IFF_UP = 0x8913, 0x8914, 0x1


def _write(path: str, text: str):
    with open(path, "w") as f:
        f.write(text)


def enter() -> str:
    """Unshare the network namespace of this process and bring loopback up. Returns how; raises OSError."""
    lib = landlock.libc()
    how = "netns"
    if lib.unshare(CLONE_NEWNET) != 0:
        uid, gid = os.geteuid(), os.getegid()
        if lib.unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0:
            raise OSError(ctypes.get_errno(), "no network namespace could be made (root, or an unprivileged user namespace, is needed)")
        _write("/proc/self/setgroups", "deny")
        _write("/proc/self/uid_map", f"{uid} {uid} 1")      # the same uid inside, so the workspace stays the shell's
        _write("/proc/self/gid_map", f"{gid} {gid} 1")
        how = "userns+netns"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        flags = struct.unpack("16sH22x", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH22x", b"lo", 0)))[1]
        fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH22x", b"lo", flags | IFF_UP))
    return how


def listen(port: int) -> socket.socket:
    """The proxy's socket inside the namespace, on the port the policy names."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", port))
    s.listen(64)
    return s
