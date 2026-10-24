"""Landlock through ctypes: no C extension, no dependency, the kernel does the work.

Landlock (Linux 5.13+) lets an unprivileged process restrict itself and every child it will
ever start: filesystem access per path (ABI 1), TCP bind/connect per port (ABI 4), signal and
abstract-socket scoping (ABI 6). Once applied, no descendant can lift it, root included. That
inheritance is why SHarness enforces at the root of the process tree (sharness.ai/process-tree).

What is here is the smallest useful subset: a ruleset, path rules, port rules, restrict self.
Measured in this project's experiments (see experiments/README.md); the numbers behind the
design are on sharness.ai/evidence.
"""
import ctypes
import os
import stat
import struct
import sys

SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule       = 445
SYS_landlock_restrict_self  = 446
PR_SET_NO_NEW_PRIVS         = 38

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH      = 1
LANDLOCK_RULE_NET_PORT          = 2

# filesystem access rights, with the ABI that introduced each
FS_EXECUTE     = 1 << 0
FS_WRITE_FILE  = 1 << 1
FS_READ_FILE   = 1 << 2
FS_READ_DIR    = 1 << 3
FS_REMOVE_DIR  = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR   = 1 << 6
FS_MAKE_DIR    = 1 << 7
FS_MAKE_REG    = 1 << 8
FS_MAKE_SOCK   = 1 << 9
FS_MAKE_FIFO   = 1 << 10
FS_MAKE_BLOCK  = 1 << 11
FS_MAKE_SYM    = 1 << 12
FS_REFER       = 1 << 13     # ABI 2
FS_TRUNCATE    = 1 << 14     # ABI 3
FS_IOCTL_DEV   = 1 << 15     # ABI 5

NET_BIND_TCP    = 1 << 0     # ABI 4
NET_CONNECT_TCP = 1 << 1     # ABI 4

SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0   # ABI 6
SCOPE_SIGNAL               = 1 << 1   # ABI 6

# rights that make sense on a plain file (the kernel refuses directory rights on a file)
ACCESS_FILE = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV

ACCESS_READ = FS_READ_FILE | FS_READ_DIR
ACCESS_EXEC = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR

_libc = None


def libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    return _libc


def _err(what):
    e = ctypes.get_errno()
    raise OSError(e, f"{what}: {os.strerror(e)}")


def abi() -> int:
    """The Landlock ABI version the running kernel supports; 0 if Landlock is unavailable."""
    if not sys.platform.startswith("linux"):
        return 0
    r = libc().syscall(ctypes.c_long(SYS_landlock_create_ruleset), ctypes.c_void_p(None),
                       ctypes.c_size_t(0), ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION))
    return r if r > 0 else 0


def fs_access_for(abi_version: int) -> int:
    """Every filesystem right this ABI knows; handling a right the ABI lacks is EINVAL."""
    bits = (1 << 13) - 1                       # ABI 1: bits 0..12
    if abi_version >= 2:
        bits |= FS_REFER
    if abi_version >= 3:
        bits |= FS_TRUNCATE
    if abi_version >= 5:
        bits |= FS_IOCTL_DEV
    return bits


class Ruleset:
    """A Landlock ruleset: handled rights, then allow-rules, then restrict_self()."""

    def __init__(self, abi_version=None, handle_fs=True, handle_net=True, scope=True):
        self.abi = abi() if abi_version is None else abi_version
        if self.abi < 1:
            raise OSError("Landlock is not available on this kernel")
        self.handled_fs = fs_access_for(self.abi) if handle_fs else 0
        self.handled_net = (NET_BIND_TCP | NET_CONNECT_TCP) if (handle_net and self.abi >= 4) else 0
        self.scoped = (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if (scope and self.abi >= 6) else 0
        # struct landlock_ruleset_attr grew with the ABI: {fs}, {fs, net}, {fs, net, scoped}
        if self.abi >= 6:
            attr = struct.pack("<QQQ", self.handled_fs, self.handled_net, self.scoped)
        elif self.abi >= 4:
            attr = struct.pack("<QQ", self.handled_fs, self.handled_net)
        else:
            attr = struct.pack("<Q", self.handled_fs)
        buf = ctypes.create_string_buffer(attr, len(attr))
        self.fd = libc().syscall(ctypes.c_long(SYS_landlock_create_ruleset), buf,
                                 ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
        if self.fd < 0:
            _err("landlock_create_ruleset")
        self.rules = []

    def add_path(self, path, access) -> bool:
        """Allow `access` beneath `path`. Returns False (and adds no rule) if the path is absent."""
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except FileNotFoundError:
            return False
        try:
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                access &= ACCESS_FILE
            access &= self.handled_fs
            if not access:
                return False
            attr = struct.pack("<Qi", access, fd)          # packed: u64 allowed_access, s32 parent_fd
            buf = ctypes.create_string_buffer(attr, len(attr))
            if libc().syscall(ctypes.c_long(SYS_landlock_add_rule), ctypes.c_int(self.fd),
                              ctypes.c_uint32(LANDLOCK_RULE_PATH_BENEATH), buf, ctypes.c_uint32(0)) < 0:
                _err(f"landlock_add_rule({path})")
        finally:
            os.close(fd)
        self.rules.append(("path", path, access))
        return True

    def add_port(self, port, access=NET_CONNECT_TCP):
        if not self.handled_net:
            raise OSError("Landlock network rules need ABI 4 or later")
        attr = struct.pack("<QQ", access, port)
        buf = ctypes.create_string_buffer(attr, len(attr))
        if libc().syscall(ctypes.c_long(SYS_landlock_add_rule), ctypes.c_int(self.fd),
                          ctypes.c_uint32(LANDLOCK_RULE_NET_PORT), buf, ctypes.c_uint32(0)) < 0:
            _err(f"landlock_add_rule(port {port})")
        self.rules.append(("port", port, access))

    def restrict_self(self):
        """no_new_privs, then enforce: this process and all its future children, for ever."""
        if libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            _err("prctl(PR_SET_NO_NEW_PRIVS)")
        if libc().syscall(ctypes.c_long(SYS_landlock_restrict_self), ctypes.c_int(self.fd),
                          ctypes.c_uint32(0)) < 0:
            _err("landlock_restrict_self")
        os.close(self.fd)
        self.fd = -1
