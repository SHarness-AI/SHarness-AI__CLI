"""Landlock for files (ABI 1, Linux 5.13) and for TCP ports (ABI 4, Linux 6.7)."""
import time

from sharness_ai import landlock
from sharness_ai.cli.doctor.Check__Result import FAIL, PASS, WARN, Check__Result


class Check__Landlock_Files:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("landlock_files", fatal=True)
        abi = landlock.abi()
        ctx.abi = abi
        if abi < 1:
            r.status, r.message = FAIL, "Landlock is not available"
            r.hint = ("the kernel is older than 5.13, was built without CONFIG_SECURITY_LANDLOCK, or landlock is not "
                      "in the LSM list (lsm= on the kernel command line). run refuses rather than run unenforced")
        else:
            r.status, r.message = PASS, f"ABI {abi}: file rules (read, write, exec) will hold"
        return r.done(t0)


class Check__Landlock_Net:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("landlock_tcp")
        if ctx.abi >= 4:
            r.status, r.message = PASS, f"ABI {ctx.abi}: TCP port rules will hold (UDP is never covered)"
        else:
            r.status, r.message = WARN, f"ABI {ctx.abi}: no TCP rules before ABI 4 (Linux 6.7)"
            r.hint = ("a policy naming connect_tcp_ports is refused here; network: none still holds where an "
                      "empty network namespace can be made")
        return r.done(t0)
