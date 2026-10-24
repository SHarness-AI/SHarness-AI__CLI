"""Process Behaviour Policy, version 0: load, check the shape, canonicalise, hash.

The hash is the one value the person supplies from outside the agent (sharness.ai/policies).
It is SHA-256 over canonical JSON: keys sorted, no whitespace, UTF-8, integers only. With
integers only, Python's json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)
and the browser's JSON.stringify over sorted keys produce the same bytes, so the same policy
hashes the same in the CLI and in the browser mockup on sharness.ai/mockups/policy-hash.html.
RFC 8785 (JCS) is the target; floats are refused rather than canonicalised, which is the one
place the two would differ.

The shape (v0) is deliberately small; the full schema is designed on sharness.ai/policies:

    {"pbp": 1, "id": "hello",
     "files":   {"read": ["/usr", ...], "write": [], "exec": ["/usr", ...]},
     "network": "none"  |  {"connect_tcp_ports": [443]},
     "process": {"no_new_privs": true}}
"""
import hashlib
import json

PBP_VERSION = 1


class PolicyError(ValueError):
    pass


def _check_types(obj, path="$"):
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
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


def load(path) -> dict:
    with open(path, encoding="utf-8") as f:
        try:
            obj = json.load(f)
        except json.JSONDecodeError as e:
            raise PolicyError(f"{path}: not JSON ({e})") from None
    if not isinstance(obj, dict):
        raise PolicyError(f"{path}: a policy is a JSON object")
    return obj


def check(policy) -> list:
    """The shape of a v0 policy. Returns a list of problems; empty means well-formed."""
    p = []
    if policy.get("pbp") != PBP_VERSION:
        p.append(f'pbp must be {PBP_VERSION}')
    if not isinstance(policy.get("id"), str) or not policy.get("id"):
        p.append("id must be a non-empty string")
    files = policy.get("files")
    if not isinstance(files, dict):
        p.append("files must be an object with read, write and exec lists")
    else:
        for k in ("read", "write", "exec"):
            v = files.get(k, [])
            if not isinstance(v, list) or not all(isinstance(x, str) and x.startswith("/") for x in v):
                p.append(f"files.{k} must be a list of absolute paths")
        for k in files:
            if k not in ("read", "write", "exec"):
                p.append(f"files.{k}: unknown key")
    net = policy.get("network")
    if net != "none":
        if not isinstance(net, dict):
            p.append('network must be "none" or {"connect_tcp_ports": [...]}')
        else:
            ports = net.get("connect_tcp_ports")
            if not isinstance(ports, list) or not all(isinstance(x, int) and 0 < x < 65536 for x in ports):
                p.append("network.connect_tcp_ports must be a list of ports (1-65535)")
            for k in net:
                if k != "connect_tcp_ports":
                    p.append(f"network.{k}: unknown key")
    proc = policy.get("process", {})
    if not isinstance(proc, dict) or proc.get("no_new_privs", True) is not True:
        p.append("process.no_new_privs must be true (v0 always sets it)")
    for k in policy:
        if k not in ("pbp", "id", "layer", "files", "network", "process", "notes"):
            p.append(f"{k}: unknown key")
    try:
        canonical(policy)
    except PolicyError as e:
        p.append(str(e))
    return p


def summary(policy) -> str:
    files = policy.get("files", {})
    net = policy.get("network")
    net_s = "none" if net == "none" else f"tcp connect to ports {net.get('connect_tcp_ports')}"
    return (f"read {len(files.get('read', []))} path(s), write {len(files.get('write', []))}, "
            f"exec {len(files.get('exec', []))}; network {net_s}")
