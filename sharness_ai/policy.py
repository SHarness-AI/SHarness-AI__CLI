"""Process Behaviour Policy, version 0: load, check the shape, canonicalise, hash, advise.

The hash is the one value the person supplies from outside the agent (sharness.ai/design/policies).
It is SHA-256 over canonical JSON: keys sorted, no whitespace, UTF-8, integers only. With
integers only, Python's json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)
and the browser's JSON.stringify over sorted keys produce the same bytes, so the same policy
hashes the same in the CLI and in the browser mockup on sharness.ai/explain/mockups/policy-hash.html.
RFC 8785 (JCS) is the target; floats are refused rather than canonicalised, which is the one
place the two would differ. Two more places where they would differ are refused too: integers
beyond 2**53 - 1 (JavaScript rounds them) and strings with lone surrogates (Python cannot encode
them as UTF-8, JavaScript escapes them).

The shape (v0) is deliberately small; the full schema is designed on sharness.ai/design/policies:

    {"pbp": 1, "id": "hello",
     "files":   {"read": ["/usr", ...], "write": [], "exec": ["/usr", ...]},
     "network": "none"  |  {"connect_tcp_ports": [443]},
     "process": {"no_new_privs": true, "max_memory_mb": 256, "max_pids": 16}}

process.max_memory_mb and process.max_pids are optional: a cap on the child's address space and
process count (RLIMIT_AS, RLIMIT_NPROC, and a cgroup where one can be made).

Paths are read as written: a policy is reviewed by a person, so what the person reads must be
what the kernel binds. check() therefore refuses paths that are not normalised ("/usr/../etc",
"/usr/", "//usr") and paths with control characters; run refuses a writable path that resolves
somewhere else through a symlink. A policy file with a duplicate key is refused for the same
reason: two values on the page, one in the hash.
"""
import hashlib
import json
import os
import posixpath
import re

PBP_VERSION   = 1
MAX_SAFE_INT  = 2 ** 53 - 1        # Number.MAX_SAFE_INTEGER: the largest integer JavaScript keeps exact
MAX_FILE_SIZE = 1 << 20            # a policy is small; a megabyte of JSON is not a policy
MAX_ID_LENGTH = 200
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class PolicyError(ValueError):
    pass


def _check_types(obj, path="$"):
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INT:
            raise PolicyError(f"{path}: integers must stay within ±{MAX_SAFE_INT} (JavaScript rounds "
                              f"larger ones, so the hash would differ between implementations)")
        return
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise PolicyError(f"{path}: string contains a lone surrogate, which has no UTF-8 form") from None
        return
    if isinstance(obj, float):
        raise PolicyError(f"{path}: floats are not allowed in a policy (integers only), "
                          f"so the hash is the same in every language")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise PolicyError(f"{path}: object keys must be strings")
            _check_types(v, f"{path}.{k}")
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_types(v, f"{path}[{i}]")
        return
    raise PolicyError(f"{path}: unsupported type {type(obj).__name__}")


def canonical(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, UTF-8, no NaN, no floats."""
    _check_types(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def policy_hash(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


def _no_duplicate_keys(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise PolicyError(f"duplicate key {k!r}: a policy must say each thing once")
        seen[k] = v
    return seen


def load(path) -> dict:
    """Read a policy file. Refuses: not JSON, not an object, a duplicate key, over a megabyte."""
    if os.path.getsize(path) > MAX_FILE_SIZE:
        raise PolicyError(f"{path}: larger than {MAX_FILE_SIZE} bytes; a policy is a small file")
    with open(path, encoding="utf-8") as f:
        try:
            obj = json.load(f, object_pairs_hook=_no_duplicate_keys)
        except json.JSONDecodeError as e:
            raise PolicyError(f"{path}: not JSON ({e})") from None
        except RecursionError:
            raise PolicyError(f"{path}: nested too deeply") from None
        except PolicyError as e:
            raise PolicyError(f"{path}: {e}") from None
    if not isinstance(obj, dict):
        raise PolicyError(f"{path}: a policy is a JSON object")
    return obj


def path_problem(p) -> str:
    """Why `p` is not acceptable as a policy path, or ''. A policy path is absolute, normalised
    (no `..`, `.`, `//` or trailing slash, so it reads as it binds) and printable."""
    if not isinstance(p, str) or not p.startswith("/"):
        return "must be an absolute path"
    if CONTROL.search(p):
        return "contains a control character"
    if p != "/" and (posixpath.normpath(p) != p or p.endswith("/") or p.startswith("//")):
        return f"is not normalised (write it as {posixpath.normpath(p)!r})"
    return ""


def check(policy) -> list:
    """The shape of a v0 policy. Returns a list of problems; empty means well-formed."""
    p = []
    if policy.get("pbp") != PBP_VERSION:
        p.append(f'pbp must be {PBP_VERSION}')
    pid = policy.get("id")
    if not isinstance(pid, str) or not pid:
        p.append("id must be a non-empty string")
    elif len(pid) > MAX_ID_LENGTH or CONTROL.search(pid):
        p.append(f"id must be at most {MAX_ID_LENGTH} printable characters")
    files = policy.get("files")
    if not isinstance(files, dict):
        p.append("files must be an object with read, write and exec lists")
    else:
        for k in ("read", "write", "exec"):
            v = files.get(k, [])
            if not isinstance(v, list):
                p.append(f"files.{k} must be a list of absolute paths")
                continue
            for x in v:
                why = path_problem(x)
                if why:
                    p.append(f"files.{k}: {x!r} {why}")
        for k in files:
            if k not in ("read", "write", "exec"):
                p.append(f"files.{k}: unknown key")
    net = policy.get("network")
    if net != "none":
        if not isinstance(net, dict):
            p.append('network must be "none" or {"connect_tcp_ports": [...]}')
        else:
            ports = net.get("connect_tcp_ports")
            if (not isinstance(ports, list)
                    or not all(isinstance(x, int) and not isinstance(x, bool) and 0 < x < 65536 for x in ports)):
                p.append("network.connect_tcp_ports must be a list of ports (1-65535)")
            for k in net:
                if k != "connect_tcp_ports":
                    p.append(f"network.{k}: unknown key")
    proc = policy.get("process", {})
    if not isinstance(proc, dict) or proc.get("no_new_privs", True) is not True:
        p.append("process.no_new_privs must be true (v0 always sets it)")
    else:
        for k in ("max_memory_mb", "max_pids"):
            v = proc.get(k)
            if v is not None and (isinstance(v, bool) or not isinstance(v, int) or v < 0):
                p.append(f"process.{k} must be a non-negative integer")
        for k in proc:
            if k not in ("no_new_privs", "max_memory_mb", "max_pids"):
                p.append(f"process.{k}: unknown key")
    for k in policy:
        if k not in ("pbp", "id", "layer", "files", "network", "process", "notes"):
            p.append(f"{k}: unknown key")
    try:
        canonical(policy)
    except PolicyError as e:
        p.append(str(e))
    return p


def _beneath(path, prefix) -> bool:
    return path == prefix or prefix == "/" or path.startswith(prefix + "/")


def advice(policy) -> list:
    """Things a well-formed policy may still want to hear. The hash names a policy; it does not
    judge it. These lines do, a little: each is a known way to grant more than the page suggests."""
    a = []
    files = policy.get("files", {}) if isinstance(policy.get("files"), dict) else {}
    read, write, exe = (files.get(k, []) for k in ("read", "write", "exec"))
    for w in write:
        for e in exe:
            if _beneath(w, e) or _beneath(e, w):
                a.append(f"{w!r} is writable and {e!r} is executable, and one is beneath the other: "
                         f"a dropped file can run. Keep write and exec apart")
    for k, v in (("read", read), ("write", write), ("exec", exe)):
        if "/" in v:
            a.append(f"files.{k} grants the whole filesystem ('/')")
    for w in write:
        if any(_beneath(w, d) for d in ("/proc", "/sys", "/dev", "/etc", "/boot")):
            a.append(f"files.write {w!r}: writing under system paths can change the system's behaviour")
        if w in ("/tmp", "/var/tmp"):  # noqa: S108 - naming the shared directories is the point  # nosec B108
            a.append(f"files.write {w!r}: shared with every other process on the machine")
    if "/etc" in exe:
        a.append("files.exec '/etc': nothing in /etc needs to run; list it under read only")
    if "/proc" in read or "/" in read:
        a.append("files.read covers /proc: the child can read other processes' command lines and environment")
    net = policy.get("network")
    if net == "none":
        a.append("network none: Landlock does not see Unix-domain sockets by path (a Docker socket, an "
                 "X11 socket, a local server); only a mount namespace or a separate uid closes them")
    elif isinstance(net, dict):
        a.append("network ports: v0 names ports, not hosts; the child may reach any host on those ports")
    proc = policy.get("process", {}) if isinstance(policy.get("process"), dict) else {}
    if proc.get("max_memory_mb") is None:
        a.append("no process.max_memory_mb: the child can take all the memory")
    if proc.get("max_pids") is None:
        a.append("no process.max_pids: the child can fork without limit")
    a.append("the child inherits this process's environment variables; v0 has no row for them")
    return a


def summary(policy) -> str:
    files = policy.get("files", {})
    net = policy.get("network")
    net_s = "none" if net == "none" else f"tcp connect to ports {net.get('connect_tcp_ports')}"
    proc = policy.get("process", {})
    caps = "".join(f"; {k.replace('max_', 'max ')} {proc[k]}" for k in ("max_memory_mb", "max_pids") if proc.get(k) is not None)
    return (f"read {len(files.get('read', []))} path(s), write {len(files.get('write', []))}, "
            f"exec {len(files.get('exec', []))}; network {net_s}{caps}")
