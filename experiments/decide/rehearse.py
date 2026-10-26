"""rehearse: run a command in a twin of the workspace, under a policy that refuses the network and
every write outside the twin, traced; report what it tried to do; decide from facts, not from the
command's shape. Prototype, 26 Oct 2026, standard library only. A Setting wherever the process
that asks is the one that would run the command; the kernel's refusals inside the twin are real."""
import json, os, re, shutil, subprocess, sys, tempfile

def rehearse(cmd, workspace, policy_path, timeout=60):
    twin = tempfile.mkdtemp(prefix="rehearsal-")           # sharness.fs.disk.twin, the cheap form: a copy
    shutil.copytree(workspace, twin, dirs_exist_ok=True, symlinks=True)
    base = json.load(open(policy_path))
    pol = dict(base); pol["id"] = base["id"] + "-rehearsal"
    pol["files"] = {"read": sorted(set(base["files"]["read"]) | {twin, "/tmp"}),
                    "write": [twin, "/tmp", "/dev/null"],              # the twin is the only writable place
                    "exec": base["files"]["exec"]}
    pol["network"] = "none"                                            # a rehearsal never reaches the world
    pol["notes"] = "rehearsal policy derived from " + base["id"]
    pfile = os.path.join(twin, ".rehearsal-policy.json"); json.dump(pol, open(pfile, "w"))
    trace = os.path.join(tempfile.gettempdir(), "rehearsal-trace.txt")
    argv = ["strace", "-f", "-qq", "-e", "trace=openat,execve,connect,unlink,unlinkat,rename,renameat2,mkdir,mkdirat,clone,clone3,fork,vfork", "-e", "signal=none", "-s", "160", "-o", trace,
            "sharness-ai", "run", "--quiet", "--best-effort", "--policy", pfile, "--", "sh", "-c", cmd]
    try:
        r = subprocess.run(argv, cwd=twin, capture_output=True, text=True, timeout=timeout)
        exit_code, out = r.returncode, (r.stdout + r.stderr)[-600:]
    except subprocess.TimeoutExpired:
        exit_code, out = "timeout", ""
    facts = read_trace(trace, twin)
    facts.update(exit=exit_code, twin=twin, output_tail=out.strip().splitlines()[-3:])
    return facts, pol

def read_trace(path, twin):
    pids, start = set(), None
    writes, writes_refused, reads_refused, execs, connects, deletes = set(), set(), set(), [], set(), set()
    for line in open(path):
        m = re.match(r"(\d+)\s+(.*)", line)
        if not m: continue
        pid, rest = m.group(1), m.group(2)
        if start is None and 'execve("/usr/bin/sh"' in rest or start is None and 'execve("/bin/sh"' in rest:
            start = pid; pids.add(pid)
        if pid not in pids: continue
        c = re.search(r"(?:clone|clone3|fork|vfork)(?:\(.*\)|.*resumed>.*)\s*=\s*(\d+)\s*$", rest)
        if c: pids.add(c.group(1))
        e = re.search(r'execve\("([^"]+)"', rest)
        if e and "ENOENT" not in rest and "EACCES" not in rest: execs.append(e.group(1))
        o = re.search(r'openat\(\w+, "([^"]+)", ([^)]*)\)\s*=\s*(-?\d+)(?: (E\w+))?', rest)
        if o:
            p, flags, ret, err = o.group(1), o.group(2), int(o.group(3)), o.group(4)
            p = p if p.startswith("/") else os.path.normpath(os.path.join(twin, p))
            shown = p.replace(twin, "<workspace>")
            w = any(f in flags for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))
            if w and ret >= 0: writes.add(shown)
            elif w and err == "EACCES": writes_refused.add(shown)
            elif not w and err == "EACCES": reads_refused.add(shown)
        d = re.search(r'unlink(?:at)?\((?:\w+, )?"([^"]+)"', rest)
        if d: deletes.add(d.group(1).replace(twin, "<workspace>"))
        n = re.search(r"connect\(\d+, \{sa_family=(\w+)(.*?)\}.*=\s*(-?\d+)(?: (E\w+))?", rest)
        if n:
            port = re.search(r"sin_port=htons\((\d+)\)", n.group(2))
            connects.add(f"{n.group(1)}{' port ' + port.group(1) if port else ''} -> {n.group(4) or 'ok'}")
    return dict(writes=sorted(writes), writes_refused=sorted(writes_refused), reads_refused=sorted(reads_refused),
                execs=sorted(set(execs)), connects=sorted(connects), deletes=sorted(deletes), processes=len(pids))

def decide(facts, base):
    reasons = []
    if facts["connects"]: reasons.append("tried the network: " + "; ".join(facts["connects"]))
    if facts["writes_refused"]: reasons.append("tried to write outside the workspace: " + ", ".join(facts["writes_refused"][:5]))
    if facts["reads_refused"]: reasons.append("the kernel refused these reads and the command went on: " + ", ".join(facts["reads_refused"][:4]))
    if facts["deletes"]: reasons.append("deletes: " + ", ".join(facts["deletes"][:5]))
    if facts["exit"] == "timeout": reasons.append("did not finish in the rehearsal")
    if facts["writes_refused"]: kind = "deny"
    elif facts["connects"] or facts["deletes"] or facts["exit"] == "timeout": kind = "ask"
    else: kind = "allow"
    summary = f"{len(facts['writes'])} write(s) inside the workspace; {len(facts['execs'])} program(s) run; {facts['processes']} process(es); exit {facts['exit']}"
    return kind, summary, reasons

if __name__ == "__main__":
    workspace, policy_path, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
    facts, pol = rehearse(cmd, workspace, policy_path)
    kind, summary, reasons = decide(facts, pol)
    print(f"$ {cmd}\n  -> {kind.upper():5s} {summary}")
    for r in reasons: print(f"     {r}")
    print(f"     wrote: {facts['writes'][:6]}\n     ran:   {[os.path.basename(e) for e in facts['execs']]}")
    shutil.rmtree(facts["twin"], ignore_errors=True)
