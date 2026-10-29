"""Run one command under a v0 Process Behaviour Policy.

    sharness-ai run --policy p.json [--expect-hash sha256:…] [--best-effort] -- cmd args…

What happens, in the child, before exec:
  1. Every file descriptor above 2 is closed: Landlock binds new opens, not what was open
     already, so an inherited descriptor would be a hole in the policy.
  2. network "none": a new, empty network namespace when this process may make one
     (unshare(CLONE_NEWNET); root, or an unprivileged user namespace around it). Otherwise,
     Landlock denies every TCP bind and connect (ABI 4+). Landlock does not see UDP, so
     without a namespace DNS lookups still go out; the result says which happened. If neither
     is available the policy cannot be kept and nothing runs.
  3. process.max_memory_mb / max_pids: RLIMIT_AS and RLIMIT_NPROC on the child, and a cgroup
     (memory.max, pids.max) when /sys/fs/cgroup is writable here (root, or a delegated subtree).
     RLIMIT_NPROC does not bind uid 0, so for root a pids cgroup is the only cap; without one
     the policy cannot be kept and nothing runs.
  4. prctl(PR_SET_NO_NEW_PRIVS).
  5. A Landlock ruleset: read, write and exec rights beneath the policy's paths, TCP connect
     to the policy's ports, nothing else. A writable path is never executable. A writable path
     that resolves somewhere else through a symlink is refused: the policy names what the kernel
     binds. restrict_self() makes it final for this process and every descendant.

A row of the policy that cannot be enforced here is a refusal, not a warning: the command does
not run (exit 126). `--best-effort` turns those refusals into a line on stderr and runs anyway,
so an operator can choose; the line is printed either way. What Landlock never covers (Unix
sockets by path, the environment the child inherits) is said on stderr too.

Who runs this decides what it is. Applied by a process to its own children it is a Boundary
for them and only a Setting for the process that applied it (which could have skipped it).
That is the whole argument of sharness.ai/design/policies §2, and the reason the end state is a
launcher above the agent, not a command the agent runs.
"""
import ctypes
import errno
import os
import sys

from sharness_ai import landlock, limits
from sharness_ai.policy import PolicyError, check, policy_hash

CLONE_NEWUSER = 0x10000000
CLONE_NEWNET  = 0x40000000
EXIT_REFUSED  = 125           # the policy was refused, nothing ran
EXIT_APPLY    = 126           # the policy could not be applied, nothing ran

UNIX_SOCKET_GAP = "Unix-domain sockets by path are not covered (Landlock has no rule for them)"
ENV_GAP         = "the child inherits this process's environment variables (v0 has no row for them)"


def unavailable() -> str:
    """Why this runtime cannot enforce a policy at all, or '' if it might.

    A WebAssembly runtime (Pyodide, emscripten) has no kernel and no processes: there is no
    child to confine, so `run` and `hello` refuse there, while hashing, checking and translating
    a policy work unchanged. Landlock's absence on a real kernel is checked separately."""
    if sys.platform == "emscripten" or not hasattr(os, "fork"):
        return (f"this runtime ({sys.platform}) has no kernel and cannot start processes, so there is "
                f"no child to confine; policy hash, check and translate work here, run and hello need Linux")
    return ""


def loopback_only() -> bool:
    """True when this process's network namespace has no interface but `lo` (the shell's, since
    security review 2): then UDP has no route out either, and nothing resolves."""
    try:
        with open("/proc/self/net/dev") as f:
            names = [line.split(":", 1)[0].strip() for line in f.readlines()[2:] if ":" in line]
    except OSError:
        return False
    return names == ["lo"]


def network_plan(net, abi: int, netns: str, loopback: bool = False):
    """What the network row means here. Returns (refusals, gaps): refusals are rows that cannot
    be enforced at all; gaps are what the enforcement that is possible still leaves open."""
    refusals, gaps = [], []
    if net == "none":
        if not netns and abi < 4:
            refusals.append("network none: no network namespace could be made and Landlock ABI "
                            f"{abi} has no TCP rules, so the child would have the network")
        elif not netns:
            gaps.append("UDP (DNS lookups) is not covered: no network namespace, Landlock sees TCP only")
        gaps.append(UNIX_SOCKET_GAP)
    else:
        ports = list(net.get("connect_tcp_ports", []))
        if abi < 4:
            refusals.append(f"network.connect_tcp_ports {ports}: Landlock ABI {abi} has no TCP rules, "
                            f"so every port would be open")
        else:
            gaps.append("UDP is not covered by Landlock port rules; here the network namespace has loopback "
                        "only, so UDP has no route out" if loopback else
                        "UDP is not covered by Landlock port rules; DNS still resolves")
    return refusals, gaps


def limits_plan(mem, pids, cgroup_applied, euid: int):
    """What the caps mean here: (refusals, gaps)."""
    refusals, gaps = [], []
    if pids is not None and not any("pids" in c for c in cgroup_applied) and not limits.nproc_binds(euid):
        refusals.append(f"process.max_pids {pids}: RLIMIT_NPROC does not bind uid 0 and no pids cgroup "
                        f"could be made (/sys/fs/cgroup not writable), so the count would be unlimited")
    if mem and not any("memory" in c for c in cgroup_applied):
        gaps.append("memory: RLIMIT_AS only (no memory cgroup could be made); the cap is on address "
                    "space, which a child can exhaust differently from resident memory")
    return refusals, gaps


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
        "unix_sockets_covered": False,
        "env_inherited": True,
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


def resolved_elsewhere(policy: dict) -> list:
    """Writable paths that exist and resolve to a different path (a symlink somewhere in them).
    Checked in the parent before anything runs, and again by the child on the very descriptor
    the rule is bound to. A read or exec path may resolve elsewhere (/lib64 → /usr/lib64 on a
    merged-/usr system); a writable one may not, because the page would then grant less than
    the kernel does."""
    out = []
    for p in policy.get("files", {}).get("write", []):
        if os.path.lexists(p):
            real = os.path.realpath(p)
            if real != p:
                out.append((p, real))
    return out


def apply(policy: dict, best_effort: bool = False) -> dict:
    """Apply the policy to the calling process. Irreversible. Returns what was applied.
    Raises PolicyError when a row cannot be enforced here (unless best_effort)."""
    problems = check(policy)
    if problems:
        raise PolicyError("; ".join(problems))
    abi = landlock.abi()
    applied = {"netns": "", "landlock_abi": abi, "paths": 0, "missing": [], "resolved": [],
               "ports": [], "limits": [], "gaps": [], "refused": []}
    net = policy.get("network")
    if net == "none":
        applied["netns"] = _unshare_net()
    refusals, gaps = network_plan(net, abi, applied["netns"], loopback_only())
    proc = policy.get("process", {})
    mem, pids = proc.get("max_memory_mb"), proc.get("max_pids")
    if mem or pids is not None:
        cg, _ = limits.cgroup(os.getpid(), mem, pids)        # the parent removes it afterwards
        applied["limits"] += cg
        rl, rl_gaps = limits.rlimits(mem, pids)
        applied["limits"] += rl
        r2, g2 = limits_plan(mem, pids, cg, os.geteuid())
        refusals += r2
        gaps += g2 + rl_gaps
    gaps.append(ENV_GAP)
    applied["gaps"] = gaps
    if refusals and not best_effort:
        raise PolicyError("cannot be enforced here: " + "; ".join(refusals))
    applied["refused"] = refusals
    rs = landlock.Ruleset(handle_net=True)
    files = policy.get("files", {})
    for kind, access in (("read", landlock.ACCESS_READ), ("exec", landlock.ACCESS_EXEC),
                         ("write", landlock.access_write(rs.handled_fs))):
        for p in files.get(kind, []):
            bound = rs.add_path(p, access, bound_to=p if kind == "write" else None)
            if bound is None:
                applied["missing"].append(p)
            else:
                applied["paths"] += 1
                if bound != p:
                    applied["resolved"].append((p, bound))
    if net != "none" and rs.handled_net:
        for port in net.get("connect_tcp_ports", []):
            rs.add_port(port, landlock.NET_CONNECT_TCP)
            applied["ports"].append(port)
    rs.restrict_self()
    return applied


def _say(text):
    """stderr by file descriptor: after closerange the child trusts only 0, 1 and 2."""
    os.write(2, text.encode("utf-8", "replace"))


def _say_list(lines, head):
    if lines:
        _say(f"sharness-ai run: {head}:\n" + "".join(f"  - {x}\n" for x in lines))


def run(policy: dict, argv: list, expect_hash: str = None, verbose: bool = False,
        best_effort: bool = False) -> int:
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
    reason = unavailable()
    if reason:
        print(f"sharness-ai run: refused. {reason}. Nothing ran.", file=sys.stderr)
        return EXIT_APPLY
    if landlock.abi() < 1:
        print("sharness-ai run: refused. Landlock is not available on this kernel, so the "
              "policy could not be enforced. Nothing ran.", file=sys.stderr)
        return EXIT_APPLY
    elsewhere = resolved_elsewhere(policy)
    if elsewhere:
        print("sharness-ai run: refused. A writable path resolves somewhere else, so the policy would "
              "grant more than it says:\n  " + "\n  ".join(f"{p} -> {r}" for p, r in elsewhere)
              + "\nName the real path in the policy. Nothing ran.", file=sys.stderr)
        return EXIT_REFUSED
    if verbose:
        print(f"sharness-ai run: policy {policy.get('id')} {h}; plan {plan(policy)}", file=sys.stderr)
    pid = os.fork()
    if pid == 0:                                   # child
        try:
            os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            applied = apply(policy, best_effort=best_effort)
            if verbose:
                _say(f"sharness-ai run: applied {applied}\n")
            _say_list(applied["refused"], "NOT enforced (--best-effort)")
            _say_list(applied["gaps"], "not covered here")
            os.environ["SHARNESS_AI_POLICY_HASH"] = h
            os.environ["SHARNESS_AI_POLICY_ID"] = str(policy.get("id"))
            os.execvp(argv[0], argv)  # noqa: S606 - the policy is applied; running the command is the job
        except BaseException as e:                 # noqa: BLE001 - the child must not return
            try:
                _say(f"sharness-ai run: could not apply the policy or start the command: {e}. Nothing ran.\n")
            finally:
                os._exit(EXIT_APPLY)
    _, status = os.waitpid(pid, 0)
    proc = policy.get("process", {})
    if proc.get("max_memory_mb") or proc.get("max_pids") is not None:
        limits.remove([f"{limits.CG}/{limits.NAME}/{pid}", f"{limits.CG}/memory/{limits.NAME}/{pid}",
                       f"{limits.CG}/pids/{limits.NAME}/{pid}"])
    return os.waitstatus_to_exitcode(status)
