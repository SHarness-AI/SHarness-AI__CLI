"""A document walked down the levels: one Step per level with its document, its hash and what
the step said (unheld rows, pass-through rows, the sentence). Level 2 in this MVP is the v0
policy, the kernel being the only door; level 1 is derived from it (what the kernel is told);
level 0 is what `hello` last measured here, when it did."""
import hashlib
from dataclasses import dataclass, field

from sharness_ai.level.l3.L3 import L3
from sharness_ai.level.l4.L4 import L4
from sharness_ai.level.l5.L5 import L5
from sharness_ai.policy import PolicyError, canonical, check, policy_hash

NAMES = {5: "intent", 4: "profile", 3: "rows", 2: "manifest", 1: "kernel", 0: "ground"}
COMPILERS = {5: L5, 4: L4, 3: L3}
NOT_COVERED = ("UDP (DNS) unless an empty network namespace applied", "Unix sockets by path", "the inherited environment")


def level_of(doc: dict) -> int:
    """5, 4 or 3 from the document's `level`; 2 for a plain v0 policy; a PolicyError otherwise."""
    lv = doc.get("level")
    if lv is None:
        if not check(doc):
            return 2
        raise PolicyError("not a v0 policy and no level: " + "; ".join(check(doc)))
    if lv not in COMPILERS:
        raise PolicyError(f"level must be 3, 4 or 5 (or absent for a v0 policy), not {lv!r}")
    return lv


@dataclass
class Step:
    level   : int
    document: dict
    hash    : str
    notes   : list = field(default_factory=list)      # what this step said, in its nouns
    unheld  : list = field(default_factory=list)      # rows nothing holds here yet
    passthrough: list = field(default_factory=list)   # rows taken from a lower level

    @property
    def name(self) -> str:
        return NAMES[self.level]


def mechanisms(v0: dict) -> dict:
    """Level 1, derived: what the kernel is told for this v0 policy, as a canonical description."""
    files = v0.get("files", {})
    net = v0.get("network")
    proc = v0.get("process", {})
    ports = [] if net == "none" else list(net.get("connect_tcp_ports", []))
    return {
        "landlock_paths": {"read": len(files.get("read", [])), "write": len(files.get("write", [])), "exec": len(files.get("exec", []))},
        "landlock_tcp_ports": sorted(ports),
        "network_namespace": net == "none",
        "rlimit_as_mb": proc.get("max_memory_mb"), "rlimit_nproc": proc.get("max_pids"),
        "cgroup": [k for k in ("memory", "pids") if proc.get(f"max_{k}_mb" if k == "memory" else "max_pids") is not None],
        "no_new_privs": True, "closerange_from": 3, "env": {"SHARNESS_AI_POLICY_HASH": policy_hash(v0)},
    }


class Chain:
    def __init__(self, steps: list):
        self.steps = steps

    @classmethod
    def from_document(cls, doc: dict, ground: dict = None) -> "Chain":
        """Compile down to level 1. `ground` is the last hello result on this machine, if any."""
        steps = []
        lv = level_of(doc)
        cur = doc
        while lv >= 3:
            comp = COMPILERS[lv]
            res = comp.compile(cur)
            step = Step(lv, cur, "sha256:" + hashlib.sha256(canonical(cur)).hexdigest())
            if "sentence" in res:
                step.notes.append(res["sentence"])
            if "profile" in res:
                step.notes.append(f"profile {res['profile']['profile']} v{res['profile'].get('version', 1)}: {res['profile'].get('title', '')}")
                step.notes.append("blanks " + ", ".join(f"{k}={v if not isinstance(v, list) else ' '.join(v) or 'none'}" for k, v in res["blanks"].items()))
            step.unheld = res.get("unheld", [])
            step.passthrough = res.get("passthrough", [])
            steps.append(step)
            cur = res["document"]
            lv -= 1
        v0 = cur
        problems = check(v0)
        if problems:
            raise PolicyError("the chain ended in a v0 policy that is not well-formed: " + "; ".join(problems))
        steps.append(Step(2, v0, policy_hash(v0), notes=["the kernel is the only door here (v0): files, ports, caps"]))
        m = mechanisms(v0)
        steps.append(Step(1, m, policy_hash(m), notes=[
            f"{sum(m['landlock_paths'].values())} Landlock path rules, {len(m['landlock_tcp_ports'])} TCP port rules"
            + (", an empty network namespace where one can be made" if m["network_namespace"] else ""),
            f"RLIMIT_AS {m['rlimit_as_mb']} MiB, RLIMIT_NPROC {m['rlimit_nproc']}, cgroups {m['cgroup'] or 'none'}, no_new_privs"]))
        if ground:
            steps.append(Step(0, ground, "", notes=[f"hello: {ground.get('held')}/{ground.get('of')} held on {ground.get('at')}"]))
        return cls(steps)

    @property
    def top(self) -> Step:
        return self.steps[0]

    def at(self, level: int) -> Step:
        return next(s for s in self.steps if s.level == level)

    @property
    def v0(self) -> dict:
        return self.at(2).document

    def report(self) -> dict:
        """held, unheld, not covered: the two numbers, in the nouns of the levels walked."""
        v0 = self.v0
        files = v0.get("files", {})
        net = v0.get("network")
        held = sum(len(files.get(k, [])) for k in ("read", "write", "exec"))
        held += 0 if net == "none" else len(net.get("connect_tcp_ports", []))
        held += 1 if net == "none" else 0
        held += sum(1 for k in ("max_memory_mb", "max_pids") if v0.get("process", {}).get(k) is not None)
        unheld = [u for s in self.steps for u in s.unheld]
        passthrough = [u for s in self.steps for u in s.passthrough]
        return {"held": held, "unheld": unheld, "passthrough": passthrough, "not_covered": list(NOT_COVERED),
                "hashes": {s.level: s.hash for s in self.steps if s.hash}}
