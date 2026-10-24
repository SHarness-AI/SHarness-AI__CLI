"""Run one command under a v0 Process Behaviour Policy.

    sharness-ai run --policy p.json [--expect-hash sha256:…] -- cmd args…

What happens, in the child, before exec:
  1. network "none": a new, empty network namespace when this process may make one
     (unshare(CLONE_NEWNET); root, or an unprivileged user namespace around it). Otherwise,
     Landlock denies every TCP bind and connect (ABI 4+). Landlock does not see UDP, so
     without a namespace DNS lookups still go out; the result says which happened.
  2. prctl(PR_SET_NO_NEW_PRIVS).
  3. A Landlock ruleset: read, write and exec rights beneath the policy's paths, TCP connect
     to the policy's ports, nothing else. restrict_self() makes it final for this process
     and every descendant.

Who runs this decides what it is. Applied by a process to its own children it is a Boundary
for them and only a Setting for the process that applied it (which could have skipped it).
That is the whole argument of sharness.ai/policies §2, and the reason the end state is a
launcher above the agent, not a command the agent runs.
"""
import ctypes
import errno
import os
import sys

from sharness_ai import landlock
from sharness_ai.policy import PolicyError, check, policy_hash

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET  = 0x40000000
EXIT_REFUSED  = 125           # the policy was refused, nothing ran
EXIT_APPLY    = 126           # the policy could not be applied, nothing ran


def plan(policy: dict) -> dict:
    """What `run` will do here, computed without doing it (for --verbose and for tests)."""
    abi = landlock.abi()
    net = policy.get("network")
    return {
        "landlock_abi": abi,
        "fs": abi >= 1,
        "net_namespace_try": net == "none",
        "landlock_tcp": abi >= 4,
        "ports": [] if net == "none" else list(net.get("connect_tcp_ports", [])),
        "udp_covered_without_namespace": False,
    }


def _unshare_net() -> str:
    """Try for an empty network namespace. Returns how, or '' if it could not be done."""
    lib = landlock.libc()
    if lib.unshare(CLONE_NEWNET) == 0:
        return "netns"
    if ctypes.get_errno() != errno.EPERM:
        return ""
    # unprivileged: a user namespace first, then the network namespace inside it
    if lib.unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0:
        return "userns+netns"
    return ""


def apply(policy: dict) -> dict:
    """Apply the policy to the calling process. Irreversible. Returns what was applied."""
    problems = check(policy)
    if problems:
        raise PolicyError("; ".join(problems))
    applied = {"netns": "", "landlock_abi": landlock.abi(), "paths": 0, "missing": [], "ports": []}
    net = policy.get("network")
    if net == "none":
        applied["netns"] = _unshare_net()
    rs = landlock.Ruleset(handle_net=True)
    files = policy.get("files", {})
    for p in files.get("read", []):
        if rs.add_path(p, landlock.ACCESS_READ):
            applied["paths"] += 1
        else:
            applied["missing"].append(p)
    for p in files.get("exec", []):
        if rs.add_path(p, landlock.ACCESS_EXEC):
            applied["paths"] += 1
        else:
            applied["missing"].append(p)
    for p in files.get("write", []):
        if rs.add_path(p, rs.handled_fs):
            applied["paths"] += 1
        else:
            applied["missing"].append(p)
    if net != "none" and rs.handled_net:
        for port in net.get("connect_tcp_ports", []):
            rs.add_port(port, landlock.NET_CONNECT_TCP)
            applied["ports"].append(port)
    rs.restrict_self()
    return applied


def run(policy: dict, argv: list, expect_hash: str = None, verbose: bool = False) -> int:
    """Fork, apply the policy in the child, exec argv. Returns the child's exit code."""
    h = policy_hash(policy)
    if expect_hash is not None and expect_hash != h:
        print(f"sharness-ai run: refused. The policy hashes to {h}; the hash supplied was "
              f"{expect_hash}. Nothing ran.", file=sys.stderr)
        return EXIT_REFUSED
    problems = check(policy)
    if problems:
        print("sharness-ai run: refused. The policy is not well-formed:\n  " + "\n  ".join(problems),
              file=sys.stderr)
        return EXIT_REFUSED
    if not argv:
        print("sharness-ai run: nothing to run (give a command after --)", file=sys.stderr)
        return EXIT_REFUSED
    if landlock.abi() < 1:
        print("sharness-ai run: refused. Landlock is not available on this kernel, so the "
              "policy could not be enforced. Nothing ran.", file=sys.stderr)
        return EXIT_APPLY
    if verbose:
        print(f"sharness-ai run: policy {policy.get('id')} {h}; plan {plan(policy)}", file=sys.stderr)
    pid = os.fork()
    if pid == 0:                                   # child
        try:
            applied = apply(policy)
            if verbose:
                print(f"sharness-ai run: applied {applied}", file=sys.stderr)
            os.environ["SHARNESS_AI_POLICY_HASH"] = h
            os.environ["SHARNESS_AI_POLICY_ID"] = str(policy.get("id"))
            os.execvp(argv[0], argv)
        except BaseException as e:                 # noqa: BLE001 - the child must not return
            try:
                sys.stderr.write(f"sharness-ai run: could not apply the policy or start the "
                                 f"command: {e}\n")
                sys.stderr.flush()
            finally:
                os._exit(EXIT_APPLY)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)
