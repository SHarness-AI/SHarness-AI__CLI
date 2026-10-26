"""decide: a command, a policy, an intent -> yes, no, or a question in the person's words.
Prototype for the design page (26 Oct 2026). Standard library only. It is a Setting wherever
the process that asks is the one that would run the command; a Boundary only at sharness.bash."""
import json, os, re, shlex, shutil, sys

READ_ONLY = {"ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "echo", "pwd", "which", "stat", "file", "diff", "sort", "uniq", "tr", "cut", "awk", "python3", "pytest", "node", "sharness-ai"}
WRITERS   = {"cp", "mv", "rm", "mkdir", "touch", "tee", "sed", "rmdir", "ln", "chmod", "chown", "truncate"}
IRREVERSIBLE = {"rm", "rmdir", "truncate", "shred", "dd"}
NETWORK   = {"curl", "wget", "ssh", "scp", "nc", "pip", "pip3", "npm", "npx", "git"}
NET_GIT   = {"push", "fetch", "pull", "clone", "remote", "ls-remote"}
PRIVILEGE = {"sudo", "su", "doas", "pkexec", "setpriv"}
URL = re.compile(r"https?://([^/\s:]+)")

def split_commands(cmd):
    parts, buf, toks = [], [], shlex.split(cmd, posix=True)
    for t in toks:
        if t in ("&&", "||", ";", "|"):
            if buf: parts.append((buf, t)); buf = []
        else:
            buf.append(t)
    if buf: parts.append((buf, None))
    return parts

def under(path, prefixes):
    return any(path == p or path.startswith(p.rstrip("/") + "/") for p in prefixes)

def paths_in(args, cwd):
    out = []
    for a in args:
        if a.startswith("-"): continue
        if a.startswith(("/", "./", "../", "~")) or "/" in a or os.path.exists(os.path.join(cwd, a)):
            out.append(os.path.normpath(os.path.join(cwd, os.path.expanduser(a))))
    return out

def decide(cmd, policy, cwd, intent=""):
    rows = policy["files"]; net = policy.get("network")
    reads, writes, hosts, execs, notes, deny = [], [], [], [], [], []
    irreversible = False; ask = []
    try:
        parts = split_commands(cmd)
    except ValueError as e:
        return verdict("deny", cmd, f"the command does not parse ({e}); what cannot be read cannot be allowed", {})
    for i, (argv, op) in enumerate(parts):
        prog = argv[0]; name = os.path.basename(prog)
        exe = prog if prog.startswith(("/", ".")) else shutil.which(prog)
        if exe is None:
            deny.append(f"`{name}` is not a command this engine knows and is not on PATH"); continue
        exe = os.path.normpath(os.path.join(cwd, exe))
        execs.append(exe)
        if not under(exe, rows.get("exec", [])):
            deny.append(f"`{exe}` is outside the policy's exec rows (the workspace is writable, never executable)")
        if name in PRIVILEGE:
            deny.append(f"`{name}` asks for privilege; the policy sets no_new_privs, so it cannot work and is not asked for"); continue
        if name in ("sh", "bash", "zsh") and i > 0 and parts[i-1][1] == "|":
            deny.append("downloaded or generated text piped into a shell: the command run is not the command shown"); continue
        for u in argv:
            m = URL.search(u)
            if m: hosts.append(m.group(1))
        if name == "git" and len(argv) > 1 and argv[1] in NET_GIT: hosts.append("the configured remote")
        if name == "git" and len(argv) > 1 and argv[1] == "push":
            if any(a in ("--force", "-f", "--force-with-lease") for a in argv) or "main" in argv:
                deny.append("a force push or a push to main: a behaviour row of this policy (never force, never main)")
        if name in NETWORK and name not in ("git",) and not hosts: hosts.append("an unnamed host")
        ps = paths_in(argv[1:], cwd)
        if name in WRITERS or (name == "sed" and "-i" in argv):
            for p in ps:
                writes.append(p)
                if not under(p, rows.get("write", [])): deny.append(f"writes `{p}`, outside the policy's write rows; the kernel would refuse it")
            if name in IRREVERSIBLE: irreversible = True
        else:
            for p in ps:
                reads.append(p)
                if not under(p, rows.get("read", [])): deny.append(f"reads `{p}`, outside the policy's read rows")
    if hosts:
        if net == "none": deny.append(f"reaches {', '.join(hosts)}; the policy says network: none")
        else: ask.append(f"reaches {', '.join(sorted(set(hosts)))}; this policy names ports, not hosts, so no row holds the host (unheld)")
    if irreversible and not deny: ask.append("deletes, which cannot be undone unless the paths are tracked by git")
    facts = {"reads": sorted(set(reads)), "writes": sorted(set(writes)), "network": sorted(set(hosts)), "runs": sorted(set(execs)), "irreversible": irreversible}
    if deny: return verdict("deny", cmd, "; ".join(deny), facts)
    if ask: return verdict("ask", cmd, "; ".join(ask), facts, intent)
    return verdict("allow", cmd, "every row of this command is held by the policy", facts)

def verdict(kind, cmd, reason, facts, intent=""):
    line = []
    line.append(f"reads {len(facts.get('reads', []))} path(s)" if facts.get("reads") else "reads nothing named")
    line.append(f"writes {len(facts.get('writes', []))} path(s)" if facts.get("writes") else "writes nothing")
    line.append("network: " + ", ".join(facts["network"]) if facts.get("network") else "no network")
    line.append("irreversible" if facts.get("irreversible") else "reversible")
    q = None
    if kind == "ask":
        q = f"The agent wants to run `{cmd}`" + (f" to {intent}" if intent else "") + f". It {'; '.join(line)}. The policy cannot hold: {reason}. Allow this once, add the row, or refuse?"
    return {"decision": kind, "summary": "; ".join(line), "reason": reason, "question": q,
            "hook": {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": q or reason}}}

if __name__ == "__main__":
    policy = json.load(open(sys.argv[1])); cwd = sys.argv[2]
    for cmd, intent in json.load(open(sys.argv[3])):
        v = decide(cmd, policy, cwd, intent)
        print(f"$ {cmd}\n  -> {v['decision'].upper():5s} {v['summary']}\n     {v['reason']}" + (f"\n     Q: {v['question']}" if v['question'] else ""))
