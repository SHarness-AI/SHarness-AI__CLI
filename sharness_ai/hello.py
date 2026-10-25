"""Experiment E04: the memo's acceptance test, as far as one process can run it.

From Dinis Cruz's memo of 24 October 2026 (sharness.ai/articles/secure-harness-for-agents):
"somebody doing a hello world with Claude should be able to run this, and then know that at
the moment it's not possible for the agent to connect to the internet, it's not possible for
the agent to write to the file system".

`sharness-ai hello` builds a deny-all policy for the running interpreter (read and exec the
system and Python, read the workspace, write nowhere, no network), prints the policy's hash,
then runs small probes under it through `sharness-ai run` and checks each outcome:

    read    listing /usr                         must be allowed
    write   creating a file in /tmp              must be refused
    write   creating a file in the workspace     must be refused
    net     TCP connect to 1.1.1.1:443           must be refused
    memory  400 MiB allocated under a 128 MiB cap must be refused (MemoryError, or killed)
    hash    a wrong --expect-hash                must refuse to run anything

It is the smallest honest version: what SHarness's launcher would do for the whole agent,
done here for one child process. The caveat printed at the end is part of the result.
"""
import json
import os
import subprocess
import sys
import tempfile

from sharness_ai import landlock
from sharness_ai.policy import policy_hash

PROBES = {
    "read":      "import os; os.listdir('/usr'); print('ok')",
    "write-tmp": "open('/tmp/sharness-ai-hello.tmp', 'w').close(); print('ok')",
    "write-cwd": "open('sharness-ai-hello.tmp', 'w').close(); print('ok')",
    "net":       "import socket; socket.create_connection(('1.1.1.1', 443), timeout=5); print('ok')",
    "memory":    "b = bytearray(400 << 20); b[-1] = 1; print('ok')",
}
EXPECT = {"read": "allowed", "write-tmp": "refused", "write-cwd": "refused", "net": "refused",
          "memory": "refused", "hash": "refused"}
MAX_MEMORY_MB = 128


def hello_policy(workspace=None) -> dict:
    """Deny-all for this interpreter: the system and Python (and its virtualenv, if any) readable
    and executable, the workspace readable, nothing writable, no network."""
    ws = os.path.realpath(workspace or os.getcwd())
    py = os.path.realpath(sys.executable)
    # sys.prefix is the virtualenv when there is one: Python reads its pyvenv.cfg at start-up,
    # so without it the probe dies before it runs (same as base_prefix outside a virtualenv)
    prefixes = sorted({"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt",
                       os.path.realpath(sys.base_prefix), os.path.realpath(sys.prefix), os.path.dirname(py)})
    return {
        "pbp": 1,
        "id": "hello",
        "layer": "invocation",
        "notes": "sharness-ai hello: deny-all for one child process. Generated for this interpreter.",
        "files": {"read": sorted(set(prefixes) | {ws}), "write": [], "exec": prefixes},
        "network": "none",
        "process": {"no_new_privs": True, "max_memory_mb": MAX_MEMORY_MB},
    }


def _run_probe(policy_path, code, expect_hash=None):
    cmd = [sys.executable, "-m", "sharness_ai", "run", "--policy", policy_path]
    if expect_hash:
        cmd += ["--expect-hash", expect_hash]
    cmd += ["--", sys.executable, "-I", "-c", code]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).strip()


def _classify(name, rc, out):
    if name == "hash":
        return "refused" if rc == 125 and "Nothing ran" in out else f"ran (exit {rc})"
    if rc == 0 and out.endswith("ok"):
        return "allowed"
    last = out.strip().splitlines()[-1] if out.strip() else f"exit {rc}"
    if rc in (-9, 137) or "Killed" in out:
        return "refused (killed by the kernel: the cgroup memory cap)"
    for e in ("PermissionError", "EACCES", "ENETUNREACH", "OSError", "ConnectionRefused", "TimeoutError", "timed out",
              "MemoryError"):
        if e in out:
            return f"refused ({last[:90]})"
    return f"failed otherwise ({last[:90]})"


def hello(as_json=False) -> int:
    from sharness_ai.run import EXIT_APPLY, unavailable
    reason = unavailable()
    if reason:
        print(json.dumps({"experiment": "E04 hello", "refused": reason}) if as_json else
              f"sharness-ai hello   refused: {reason}. Nothing ran.")
        return EXIT_APPLY
    policy = hello_policy()
    h = policy_hash(policy)
    abi = landlock.abi()
    results = []
    with tempfile.TemporaryDirectory(prefix="sharness-ai-hello-") as d:
        pp = os.path.join(d, "hello.json")
        with open(pp, "w") as f:
            json.dump(policy, f, indent=1)
        for name, code in PROBES.items():
            rc, out = _run_probe(pp, code)
            results.append((name, _classify(name, rc, out), rc))
        wrong = "sha256:" + "0" * 64
        rc, out = _run_probe(pp, PROBES["read"], expect_hash=wrong)
        results.append(("hash", _classify("hash", rc, out), rc))
    held = [(n, EXPECT[n], got) for n, got, _ in results if got.startswith(EXPECT[n])]
    failed = [(n, EXPECT[n], got) for n, got, _ in results if not got.startswith(EXPECT[n])]
    netns_possible = os.geteuid() == 0
    if as_json:
        print(json.dumps({
            "experiment": "E04 hello", "policy_id": policy["id"], "policy_hash": h, "policy": policy,
            "landlock_abi": abi, "euid": os.geteuid(),
            "results": [{"probe": n, "expected": EXPECT[n], "got": g, "exit": rc} for n, g, rc in results],
            "held": len(held), "of": len(results),
        }, indent=1))
    else:
        print("sharness-ai hello   experiment E04: the memo's acceptance test, for one child process")
        print(f"policy      {policy['id']}  {h}")
        print(f"            read-only: {', '.join(policy['files']['read'])}")
        print(f"            write: none · exec: system and Python · network: none · memory: {MAX_MEMORY_MB} MiB")
        netns = ("yes (uid 0)" if netns_possible else
                 "only if an unprivileged user namespace is allowed; else Landlock denies TCP (not UDP)")
        print(f"kernel      Landlock ABI {abi or 'none'} · empty network namespace: {netns}")
        for n, got, _ in results:
            mark = "✔" if got.startswith(EXPECT[n]) else "✗"
            print(f"  {mark} {n:<10} expected {EXPECT[n]:<8} got {got}")
        print(f"result      {len(held)}/{len(results)} held")
        print("caveat      applied by this process to its own children: a Boundary for them, a Setting for "
              "whoever ran this, who could have skipped it. The launcher that makes it a Boundary for the "
              "agent too is the design: https://sharness.ai/design/policies/index.html#2-who-enforces-decides-the-barrier-kind")
    return 0 if not failed else 1
