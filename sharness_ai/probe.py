"""The grant: what a process here can do before any policy is applied.

In the Agent Behaviour Policy model a *grant* is what the subject can technically do; the
*mandate* is what it is authorised to do; the *delta* is the gap (sharness.ai/design/policies §1).
This probe measures the grant of the environment it runs in: identity, capabilities, the
kernel's sandboxing primitives, the tools present, and whether egress goes through a proxy.
Read-only. It prints names of environment variables, never their values.
"""
import os
import platform
import re
import shutil
import sys

CAP_ALL_HEX_MIN_BITS = 38          # a bounding set with this many bits on is "everything", near enough
TOOLS = ("unshare", "setpriv", "bwrap", "strace", "iptables", "nft", "useradd", "fusermount3", "criu")
CONFIG_KEYS = ("CONFIG_SECURITY_LANDLOCK", "CONFIG_SECCOMP", "CONFIG_SECRETMEM", "CONFIG_USER_NS",
               "CONFIG_CGROUP_FREEZER", "CONFIG_PKCS8_PRIVATE_KEY_PARSER", "CONFIG_FUSE_FS")
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy")


def _status():
    out = {}
    try:
        with open("/proc/self/status") as f:
            for line in f:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def _kernel_config():
    cfg = {}
    try:
        import gzip
        with gzip.open("/proc/config.gz", "rt") as f:
            for line in f:
                for k in CONFIG_KEYS:
                    if line.startswith(k + "="):
                        cfg[k] = line.strip().split("=", 1)[1]
    except OSError:
        return None
    for k in CONFIG_KEYS:
        cfg.setdefault(k, "not set")
    return cfg


def _memfd_secret():
    """memfd_secret(2), syscall 447: a page root cannot read through /proc/<pid>/mem."""
    try:
        from sharness_ai.landlock import libc
        import ctypes
        fd = libc().syscall(ctypes.c_long(447), ctypes.c_uint(0))
        if fd >= 0:
            os.close(fd)
            return True
        return False
    except Exception:
        return False


def _cgroups():
    if os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        return "v2"
    if os.path.isdir("/sys/fs/cgroup/unified"):
        return "hybrid (v1 + unified)"
    if os.path.isdir("/sys/fs/cgroup/freezer"):
        return "v1"
    return "unknown"


def probe() -> dict:
    linux = sys.platform.startswith("linux")
    st = _status() if linux else {}
    cap_eff = st.get("CapEff", "")
    cap_bnd = st.get("CapBnd", "")
    try:
        caps_all = bin(int(cap_bnd, 16)).count("1") >= CAP_ALL_HEX_MIN_BITS
    except ValueError:
        caps_all = None
    landlock_abi = 0
    if linux:
        from sharness_ai.landlock import abi
        landlock_abi = abi()
    ns = []
    if linux and os.path.isdir("/proc/self/ns"):
        ns = sorted(os.listdir("/proc/self/ns"))
    return {
        "os": sys.platform,
        "kernel": platform.release(),
        "python": platform.python_version(),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "cap_eff": cap_eff or None,
        "cap_bnd": cap_bnd or None,
        "caps_all": caps_all,
        "no_new_privs": int(st["NoNewPrivs"]) if st.get("NoNewPrivs", "").isdigit() else None,
        "seccomp": int(st["Seccomp"]) if st.get("Seccomp", "").isdigit() else None,
        "landlock_abi": landlock_abi,
        "memfd_secret": _memfd_secret() if linux else False,
        "namespaces": ns,
        "cgroups": _cgroups() if linux else None,
        "kernel_config": _kernel_config() if linux else None,
        "tools": {t: shutil.which(t) for t in TOOLS},
        "egress_proxy_vars": [v for v in PROXY_VARS if os.environ.get(v)],
        "cwd_writable": os.access(os.getcwd(), os.W_OK),
    }


def caps_label(p: dict) -> str:
    """What is in effect, then the most it could gain: CapEff and CapBnd are different questions."""
    eff, bnd = p.get("cap_eff"), p.get("cap_bnd")
    if not eff:
        return "unknown"
    try:
        n = bin(int(eff, 16)).count("1")
    except ValueError:
        return "unknown"
    now = "all" if n >= CAP_ALL_HEX_MIN_BITS else "none" if n == 0 else "some"
    gain = "full" if p.get("caps_all") else "limited" if p.get("caps_all") is not None else "unknown"
    return f"{now} in effect (CapEff {eff}); bounding set {gain} (CapBnd {bnd})"


def render(p: dict) -> str:
    def yn(v):
        return "yes" if v else "no"

    def known(v, absent="unknown"):
        return absent if v is None else v
    who = f"uid {p['uid']}" + (" (root)" if p["uid"] == 0 else "")
    caps = caps_label(p)
    tools = "  ".join(f"{t} {'✔' if path else '✗'}" for t, path in p["tools"].items())
    cfg = p.get("kernel_config")
    cfg_s = ("  ".join(f"{k.replace('CONFIG_', '')}={v}" for k, v in cfg.items())
             if cfg else "/proc/config.gz not readable")
    proxies = ", ".join(p["egress_proxy_vars"]) or "none"
    lines = [
        "sharness-ai probe   the grant: what a process here can do before any policy",
        f"identity    {who} · capabilities {caps} · NoNewPrivs {known(p['no_new_privs'])} · Seccomp {known(p['seccomp'])}",
        f"kernel      {p['os']} {p['kernel']} · Landlock ABI {p['landlock_abi'] or 'none'} · "
        f"memfd_secret {yn(p['memfd_secret'])} · cgroups {known(p['cgroups'], 'none')}",
        f"namespaces  {', '.join(p['namespaces']) or 'n/a'}",
        f"config      {cfg_s}",
        f"tools       {tools}",
        f"egress      proxy variables set: {proxies} (names only; values are never printed)",
        f"workspace   {os.getcwd()} writable: {yn(p['cwd_writable'])} · python {p['python']}",
    ]
    if p["os"] == "emscripten":
        lines.append("reading     no kernel here: this is Python compiled to WebAssembly (Pyodide). A policy can be "
                     "hashed, checked and translated here; it can be enforced only by a Linux kernel.")
    elif p["os"].startswith("linux") and not p["landlock_abi"]:
        lines.append("reading     Landlock is not available on this kernel: `run` would refuse rather than run "
                     "a command without its policy.")
    if p["uid"] == 0 and p["caps_all"]:
        lines.append("reading     this process is root with every capability and no seccomp: the grant is "
                     "everything. A policy applied from here binds its children, not itself.")
    return "\n".join(lines)
