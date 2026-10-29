"""Is there a Linux kernel at all? Pyodide and other platforms cannot enforce anything."""
import platform
import sys
import time

from sharness_ai.cli.doctor.Check__Result import FAIL, PASS, Check__Result


class Check__Kernel:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("kernel", fatal=True)
        if sys.platform == "emscripten":
            r.status, r.message = FAIL, "no kernel: Python compiled to WebAssembly (Pyodide)"
            r.hint = ("a policy can be hashed, checked, written and translated here and enforced nowhere. The Linux "
                      "tab of the playground has a kernel: https://sharness.ai/code/playground/index.html")
        elif not sys.platform.startswith("linux"):
            r.status, r.message = FAIL, f"{sys.platform}: Landlock is a Linux kernel feature"
            r.hint = "run and hello refuse here rather than pretend; a Linux machine, VM or container (5.13+) enforces"
        else:
            r.status, r.message = PASS, f"linux {platform.release()}"
        return r.done(t0)
