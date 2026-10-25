"""Resource caps for one child: memory and process count, in the kernel.

Two layers, applied in the child before exec. RLIMIT_AS (address space) and RLIMIT_NPROC are
per-process limits any uid can set on itself and cannot raise again once lowered under
no_new_privs. A cgroup (v2: memory.max, pids.max; v1: memory.limit_in_bytes, pids.max) is a
hard wall the kernel enforces on the whole subtree: exceed memory.max and the process is
OOM-killed, not throttled. The cgroup needs write access to /sys/fs/cgroup (root, or a
delegated subtree), so it is applied when it can be and reported either way.
"""
import os

try:
    import resource
except ImportError:                 # no resource module: WebAssembly runtimes such as Pyodide
    resource = None

CG = "/sys/fs/cgroup"
NAME = "sharness-ai"


def cgroup_version():
    if os.path.exists(f"{CG}/cgroup.controllers"):
        return 2
    if os.path.isdir(f"{CG}/memory") or os.path.isdir(f"{CG}/pids"):
        return 1
    return 0


def nproc_binds(euid=None) -> bool:
    """Whether RLIMIT_NPROC binds this process. The kernel exempts uid 0 (and any process with
    CAP_SYS_RESOURCE or CAP_SYS_ADMIN) from the check at fork, so as root the rlimit is set and
    does nothing; only a pids cgroup caps a root child's process count. For every other uid it
    counts that uid's processes machine-wide, not this tree's."""
    return (os.geteuid() if euid is None else euid) != 0


def rlimits(max_memory_mb=None, max_pids=None):
    """Per-process caps on the calling process; inherited by exec and by children.
    Returns (applied, gaps): what was set, and what was set but does not bind here."""
    applied, gaps = [], []
    if max_memory_mb:
        n = max_memory_mb << 20
        resource.setrlimit(resource.RLIMIT_AS, (n, n))
        applied.append(f"RLIMIT_AS={max_memory_mb}MiB")
    if max_pids is not None:
        resource.setrlimit(resource.RLIMIT_NPROC, (max_pids, max_pids))
        if nproc_binds():
            applied.append(f"RLIMIT_NPROC={max_pids}")
        else:
            gaps.append(f"RLIMIT_NPROC={max_pids} set but not binding: the kernel exempts uid 0 from it")
    return applied, gaps


def _write(path, value):
    with open(path, "w") as f:
        f.write(str(value))


def cgroup(pid, max_memory_mb=None, max_pids=None):
    """Put `pid` in a fresh cgroup with the caps. Returns (what was applied, cleanup) or ([], None)
    when cgroups are not writable here. `cleanup()` removes the cgroup once it is empty."""
    v = cgroup_version()
    if not v:
        return [], None
    applied, dirs = [], []
    try:
        if v == 2:
            d = f"{CG}/{NAME}/{pid}"
            os.makedirs(d, exist_ok=True)
            # memory.max and pids.max exist in a child only once the parent has enabled the
            # controllers in its cgroup.subtree_control; on a fresh mount (the E09 guest) the root
            # has none enabled. Best effort at both levels; the writes below say whether it worked.
            for parent in (CG, f"{CG}/{NAME}"):
                try:
                    _write(f"{parent}/cgroup.subtree_control", "+memory +pids")
                except OSError:
                    pass
            if max_memory_mb:
                _write(f"{d}/memory.max", max_memory_mb << 20)
                applied.append(f"cgroup2 memory.max={max_memory_mb}MiB")
            if max_pids is not None:
                _write(f"{d}/pids.max", max_pids)
                applied.append(f"cgroup2 pids.max={max_pids}")
            _write(f"{d}/cgroup.procs", pid)
            dirs.append(d)
        else:
            if max_memory_mb and os.path.isdir(f"{CG}/memory"):
                d = f"{CG}/memory/{NAME}/{pid}"
                os.makedirs(d, exist_ok=True)
                _write(f"{d}/memory.limit_in_bytes", max_memory_mb << 20)
                _write(f"{d}/tasks", pid)
                applied.append(f"cgroup1 memory.limit_in_bytes={max_memory_mb}MiB")
                dirs.append(d)
            if max_pids is not None and os.path.isdir(f"{CG}/pids"):
                d = f"{CG}/pids/{NAME}/{pid}"
                os.makedirs(d, exist_ok=True)
                _write(f"{d}/pids.max", max_pids)
                _write(f"{d}/tasks", pid)
                applied.append(f"cgroup1 pids.max={max_pids}")
                dirs.append(d)
    except OSError:
        for d in dirs:
            try:
                os.rmdir(d)
            except OSError:
                pass
        return [], None

    def cleanup():
        remove(dirs)
    return applied, cleanup


def remove(dirs):
    """Remove the per-child cgroups, and the sharness-ai parent when it is empty."""
    for d in dirs:
        try:
            os.rmdir(d)
        except OSError:              # a lingering grandchild; the kernel frees it later
            pass
        try:
            os.rmdir(os.path.dirname(d))
        except OSError:
            pass
