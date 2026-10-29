"""Translate a v0 Process Behaviour Policy into another enforcer's native form.

The policy is the centre; SHarness's own enforcement (Landlock, namespaces, rlimits, cgroups) is
one target among several. This module writes the same policy as what another tool would take:

    bwrap        a bubblewrap command line (namespaces, read-only and writable binds)
    docker       a `docker run` command line (read-only rootfs, binds, --network, caps, limits)
    claude-code  a settings.json fragment for Claude Code's sandbox (filesystem and network)
    kubernetes   a Pod securityContext, resources and a NetworkPolicy (YAML)
    landlock     what sharness-ai run itself applies (for completeness)

Every translation returns the text and a list of what that target does NOT enforce from the
policy, so the output is honest about the gap. That list, over all targets, is the
enforceability matrix on sharness.ai/landscape/enforceability. Nothing here runs the target;
this is `policy translate`, not `run`.
"""
import json
import shlex

TARGETS = ("bwrap", "docker", "claude-code", "kubernetes", "landlock")


def _net(policy):
    net = policy.get("network")
    return ("none", []) if net == "none" else ("ports", list(net.get("connect_tcp_ports", [])))


def _caps(policy):
    proc = policy.get("process", {})
    return proc.get("max_memory_mb"), proc.get("max_pids")


def to_bwrap(policy, cmd):
    files = policy["files"]
    kind, ports = _net(policy)
    mem, pids = _caps(policy)
    parts = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"]
    if kind == "ports":
        parts.append("--share-net")
    for p in sorted(set(files.get("read", [])) | set(files.get("exec", []))):
        if p not in files.get("write", []):
            parts += ["--ro-bind", p, p]
    for p in files.get("write", []):
        parts += ["--bind", p, p]
    parts += ["--"] + list(cmd)
    line = " ".join(shlex.quote(x) for x in parts)
    notes = ["no_new_privs: bwrap sets it (PR_SET_NO_NEW_PRIVS) for the sandboxed process"]
    if kind == "ports":
        notes.append(f"network.connect_tcp_ports {ports}: not enforced; bwrap shares or unshares the whole network, it has no port allowlist")
    if files.get("exec"):
        notes.append("files.exec: not distinct from files.read; a read-only bind is also executable in bwrap (use noexec mounts or Landlock inside)")
    if files.get("write"):
        notes.append("files.write: a writable bind is also executable in bwrap; sharness-ai run never grants execute on a writable path")
    if mem:
        notes.append(f"process.max_memory_mb {mem}: not enforced by bwrap; prefix with `prlimit --as={mem << 20}` or run under a cgroup")
    if pids is not None:
        notes.append(f"process.max_pids {pids}: not enforced by bwrap; `prlimit --nproc={pids}` or a pids cgroup")
    return line, notes


def to_docker(policy, cmd, image="python:3.12-alpine"):
    files = policy["files"]
    kind, ports = _net(policy)
    mem, pids = _caps(policy)
    parts = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges", "--user", "65534:65534",
             "--network", "none" if kind == "none" else "bridge"]
    if mem:
        parts += ["--memory", f"{mem}m"]
    if pids is not None:
        parts += ["--pids-limit", str(pids)]
    for p in sorted(set(files.get("read", [])) | set(files.get("exec", []))):
        if p not in files.get("write", []) and not p.startswith(("/usr", "/lib", "/bin", "/sbin", "/etc")):
            parts += ["-v", f"{p}:{p}:ro"]
    for p in files.get("write", []):
        parts += ["-v", f"{p}:{p}"]
    parts += [image] + list(cmd)
    line = " ".join(shlex.quote(x) for x in parts)
    notes = [f"image {image} is named by tag; pin it by digest (image@sha256:…) so the policy binds to one build",
             "files.read of system paths (/usr, /lib, /bin, /sbin, /etc): taken from the image, not bound from the host",
             "files.exec: not distinct from read; everything readable in the image is executable (Docker has no exec allowlist)"]
    if kind == "ports":
        notes.append(f"network.connect_tcp_ports {ports}: not enforced by `docker run`; needs an egress rule (iptables in the container's namespace, or a proxy)")
    if any(":" in p for p in files.get("read", []) + files.get("write", []) + files.get("exec", [])):
        notes.append("a path contains ':', which `-v host:container` cannot express; use --mount type=bind,source=…,target=…")
    notes.append("the policy hash: Docker does not check one; the launcher's --expect-hash has no equivalent")
    return line, notes


def to_claude_code(policy):
    files = policy["files"]
    kind, ports = _net(policy)
    mem, pids = _caps(policy)
    settings = {"sandbox": {"enabled": True, "allowUnsandboxedCommands": False, "failIfUnavailable": True,
                            "filesystem": {"allowWrite": list(files.get("write", []))},
                            "network": {"allowedDomains": [], "strictAllowlist": True}}}
    notes = ["files.read: not an allowlist in the sandbox; it reads most of the machine unless paths are listed in filesystem.denyRead (the policy's read list cannot be expressed as a deny list without knowing the machine)",
             "files.exec: no equivalent; the sandbox has no execute allowlist",
             "covers Bash, PowerShell and Monitor commands and their children only; the built-in file and web tools, hooks, MCP servers and the harness itself are outside it (per its documentation)"]
    if kind == "ports":
        notes.append(f"network.connect_tcp_ports {ports}: the sandbox allowlists domain names at a proxy, not ports; list the hosts in network.allowedDomains by hand")
    else:
        notes.append("network none: expressed as an empty allowedDomains with strictAllowlist; the proxy refuses every host (UDP and ICMP cannot leave the sandbox per its documentation)")
    if mem or pids is not None:
        notes.append("process.max_memory_mb / max_pids: no equivalent in the sandbox settings")
    notes.append("the policy hash: settings are read by the agent's own process (a Setting in ABP terms); managed settings make them a Boundary for the user, not for the harness")
    return json.dumps(settings, indent=2), notes


def to_kubernetes(policy, cmd, image="python:3.12-alpine", name="harnessed"):
    files = policy["files"]
    kind, ports = _net(policy)
    mem, pids = _caps(policy)
    vols, mounts = [], []
    for i, p in enumerate(sorted(set(files.get("write", [])))):
        vols.append(f"      - name: w{i}\n        emptyDir: {{}}")
        mounts.append(f"          - name: w{i}\n            mountPath: {json.dumps(p)}")   # quoted: a path is data, never YAML
    limits = f"\n          limits:\n            memory: {mem}Mi" if mem else ""
    egress = "  egress: []" if kind == "none" else "  egress:\n    - ports:\n" + "".join(f"        - protocol: TCP\n          port: {p}\n" for p in ports)
    yaml = f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
  labels: {{ app: {name} }}
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    seccompProfile: {{ type: RuntimeDefault }}
  containers:
    - name: app
      image: {image}
      args: {json.dumps(list(cmd))}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {{ drop: ["ALL"] }}
      resources:{limits or " {}"}
      volumeMounts:
{chr(10).join(mounts) if mounts else "          []"}
  volumes:
{chr(10).join(vols) if vols else "      []"}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}-egress
spec:
  podSelector: {{ matchLabels: {{ app: {name} }} }}
  policyTypes: [Egress]
{egress}
"""
    notes = [f"image {image} is named by tag; pin it by digest (image@sha256:…) so the policy binds to one build",
             "files.read: the image's filesystem, read-only; host paths are not bound (a policy's read list becomes the image's contents)",
             "files.exec: no execute allowlist in a securityContext",
             "files.write: each path becomes an emptyDir volume (not the host's folder)",
             "process.max_pids: no per-pod pids limit in the Pod spec (the kubelet's podPidsLimit is cluster-wide)",
             "seccompProfile RuntimeDefault is the runtime's default filter, not the policy's syscall list",
             "the policy hash: nothing in Kubernetes checks it; an admission controller could"]
    if kind == "ports":
        notes.append("network ports: the NetworkPolicy allows the ports to any destination; hosts are not expressible without a CIDR or a service mesh")
    return yaml, notes


def to_landlock(policy, cmd):
    line = "sharness-ai run --policy <file> -- " + " ".join(shlex.quote(x) for x in cmd)
    kind, ports = _net(policy)
    notes = ["files.read, files.exec, files.write: Landlock path rules; network: an empty namespace or Landlock TCP ports; caps: rlimits and cgroups; no_new_privs: set",
             "not yet in the CLI: per-component uids, seccomp, mutual TLS, the launcher (see sharness.ai/design/containment)"]
    if kind == "ports":
        notes.append("UDP is not covered by Landlock port rules; DNS still resolves without the namespace")
    return line, notes


def translate(policy, target, cmd=("/bin/sh", "-c", "echo hello")):
    if target == "bwrap":
        return to_bwrap(policy, cmd)
    if target == "docker":
        return to_docker(policy, cmd)
    if target == "claude-code":
        return to_claude_code(policy)
    if target == "kubernetes":
        return to_kubernetes(policy, cmd)
    if target == "landlock":
        return to_landlock(policy, cmd)
    raise ValueError(f"unknown target {target!r}; one of {', '.join(TARGETS)}")
