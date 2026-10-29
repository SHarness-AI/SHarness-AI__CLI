"""Is openssl here? A session's certificates are issued with it; the doors only verify."""
import shutil
import subprocess
import time

from sharness_ai.cli.doctor.Check__Result import PASS, WARN, Check__Result


class Check__Openssl:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("openssl")
        path = shutil.which("openssl")
        if not path:
            r.status, r.message = WARN, "no openssl: a session's certificates cannot be issued here"
            r.hint = "run and hello need no session; the doors do (sharness-ai session new). Every Linux distribution carries openssl"
            return r.done(t0)
        try:
            v = subprocess.run([path, "version"], capture_output=True, text=True, timeout=5).stdout.strip()  # noqa: S603 - found by which
        except (OSError, subprocess.SubprocessError):
            v = "openssl"
        r.status, r.message = PASS, f"{v}: sessions and doors can be made"
        return r.done(t0)
