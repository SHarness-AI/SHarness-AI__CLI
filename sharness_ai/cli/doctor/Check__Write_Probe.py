"""The proof: a child under a deny-write policy tries to write in a scratch directory. The kernel
must refuse it. Runs only when the earlier checks allow; the whole thing is sharness-ai run on
this interpreter, the way hello does it."""
import json
import os
import subprocess
import sys
import tempfile
import time

from sharness_ai.cli.doctor.Check__Result import FAIL, PASS, SKIP, WARN, Check__Result


class Check__Write_Probe:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("write_probe")
        if ctx.abi < 1 or not hasattr(os, "fork"):
            r.status, r.message = SKIP, "needs Landlock"
            return r.done(t0)
        import sharness_ai
        from sharness_ai.hello import PROBE_FLAGS, RUNNER_FLAGS, hello_policy
        pkg_parent = os.path.realpath(os.path.dirname(os.path.dirname(sharness_ai.__file__)))
        with tempfile.TemporaryDirectory(prefix="sharness-ai-doctor-") as d:
            target = os.path.join(d, "x")
            policy = hello_policy(workspace=d)                 # read the system and d; write nowhere
            for k in ("read", "exec"):                         # the package itself, wherever it is (uninstalled in CI)
                policy["files"][k] = sorted(set(policy["files"][k]) | {pkg_parent})
            pp = os.path.join(d, "policy.json")
            with open(pp, "w") as f:
                json.dump(policy, f)
            code = f"open({target!r}, 'w').close(); print('wrote')"
            env = dict(os.environ, PYTHONPATH=pkg_parent)
            cmd = [sys.executable, *RUNNER_FLAGS, "-m", "sharness_ai", "run", "--policy", pp, "--", sys.executable, *PROBE_FLAGS, "-c", code]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)  # noqa: S603 - argv list, this interpreter, our code
                rc, out, err = proc.returncode, proc.stdout.strip(), proc.stderr.strip()
            except subprocess.TimeoutExpired:
                rc, out, err = -1, "", "the probe did not finish in 60 s"
            wrote = os.path.exists(target)
        r.details = {"exit": rc, "stderr_tail": err[-200:]}
        if wrote or out.endswith("wrote"):
            r.status, r.message, r.fatal = FAIL, "a write under a deny-write policy went through", True
            r.hint = "this kernel did not enforce the rule it reported; please send sharness-ai hello --json as a report"
        elif "Permission denied" in err or "EACCES" in err:
            r.status, r.message = PASS, "the kernel refused a write the policy did not allow (EACCES)"
        else:
            r.status, r.message = WARN, f"the child did not run (exit {rc}); nothing was written, nothing proven"
            r.hint = "sharness-ai hello shows each probe and its control; the stderr tail is in --json"
        return r.done(t0)
