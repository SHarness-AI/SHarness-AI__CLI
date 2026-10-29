"""The caps: a cgroup where one can be made, RLIMIT_NPROC where it binds."""
import os
import time

from sharness_ai import limits
from sharness_ai.cli.doctor.Check__Result import PASS, WARN, Check__Result


class Check__Cgroups:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("cgroups")
        version = limits.cgroup_version()
        writable = os.access(limits.CG, os.W_OK) if version else False
        ctx.cgroup_writable = writable
        if version and writable:
            r.status, r.message = PASS, f"cgroups {version}, writable: memory and pids cgroups will be made"
        elif version:
            r.status, r.message = WARN, f"cgroups {version}, not writable: memory by RLIMIT_AS only"
            r.hint = "RLIMIT_AS caps address space, not resident memory; a writable /sys/fs/cgroup gives a real cap"
        else:
            r.status, r.message = WARN, "no cgroups mounted: memory by RLIMIT_AS only"
        return r.done(t0)


class Check__Process_Count:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("max_pids")
        euid = os.geteuid()
        if limits.nproc_binds(euid):
            r.status, r.message = PASS, f"RLIMIT_NPROC binds uid {euid}: max_pids will hold"
        elif ctx.cgroup_writable:
            r.status, r.message = PASS, "uid 0: RLIMIT_NPROC does not bind root, the pids cgroup will"
        else:
            r.status, r.message = WARN, "uid 0 and no writable cgroup: max_pids cannot be enforced"
            r.hint = "a policy with process.max_pids is refused here (--best-effort runs without it); run as a user, or make /sys/fs/cgroup writable"
        return r.done(t0)
