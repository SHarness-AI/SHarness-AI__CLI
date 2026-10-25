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


def rlimits(max_memory_mb=None, max_pids=None):
    """Per-process caps on the calling process; inherited by exec and by children."""
    applied = []
    if max_memory_mb:
        n = max_memory_mb << 20
        resource.setrlimit(resource.RLIMIT_AS, (n, n))
        applied.append(f"RLIMIT_AS={max_memory_mb}MiB")
    if max_pids is not None:
        resource.setrlimit(resource.RLIMIT_NPROC, (max_pids, max_pids))
        applied.append(f"RLIMIT_NPROC={max_pids}")
    return applied


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
            # subtree_control is only needed when nesting below the root's children
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
