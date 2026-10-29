"""Can `network: none` get an empty network namespace? uid 0 can; an unprivileged user can only
through a user namespace, where the distribution allows one. Tried for real in a child process,
which is thrown away."""
import os
import time

from sharness_ai.cli.doctor.Check__Result import PASS, SKIP, WARN, Check__Result


class Check__Network_Namespace:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("network_namespace")
        if not hasattr(os, "fork"):
            r.status, r.message = SKIP, "no processes here"
            return r.done(t0)
        how = self._try()
        if how:
            r.status, r.message = PASS, f"an empty network namespace can be made ({how})"
        else:
            r.status, r.message = WARN, "no network namespace: network none falls back to Landlock TCP rules"
            r.hint = ("UDP (DNS) is then not covered. uid 0 or an unprivileged user namespace "
                      "(kernel.unprivileged_userns_clone, user.max_user_namespaces) gives the namespace")
        return r.done(t0)

    @staticmethod
    def _try() -> str:
        from sharness_ai.run import _unshare_net
        rd, wr = os.pipe()
        pid = os.fork()
        if pid == 0:                                             # the child: try, report, vanish
            try:
                os.close(rd)
                how = _unshare_net()
                os.write(wr, how.encode())
            finally:
                os._exit(0)
        os.close(wr)
        how = os.read(rd, 64).decode()
        os.close(rd)
        os.waitpid(pid, 0)
        return how
