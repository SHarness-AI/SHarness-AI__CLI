"""Level 5: intent, one sentence with blanks, compiled to a profile with its blanks (level 4).

`{"pbp": 1, "level": 5, "contain": {"agent": "claude", "workspace": "/abs/path",
"sites": ["github.com"], "secrets": [], "profile": "coding-agent", "budget": {"memory_mb": 2048, "pids": 64}}}`.
The sentence is the document read back: "contain claude to /abs/path, github.com, no secrets".
The profile defaults to coding-agent; the budget to the profile's. Compilation fills the level-4
blanks from the sentence and nothing else."""
import os

from sharness_ai.level.l4.L4 import L4
from sharness_ai.policy import PolicyError

LEVEL = 5
DEFAULT_PROFILE = "coding-agent"


class L5:
    level = LEVEL
    emits = 4

    @staticmethod
    def check(doc: dict) -> list:
        p = []
        if doc.get("level") != LEVEL:
            p.append(f"level must be {LEVEL}")
        c = doc.get("contain")
        if not isinstance(c, dict):
            return p + ["contain must be an object: agent, workspace, sites, secrets, profile, budget"]
        if not isinstance(c.get("agent"), str) or not c.get("agent"):
            p.append("contain.agent must name the agent (a word)")
        ws = c.get("workspace")
        if not isinstance(ws, str) or not ws.startswith("/") or os.path.normpath(ws) != ws:
            p.append("contain.workspace must be an absolute, normalised path")
        for k in ("sites", "secrets"):
            if k in c and (not isinstance(c[k], list) or not all(isinstance(x, str) for x in c[k])):
                p.append(f"contain.{k} must be a list of strings")
        if "profile" in c and c["profile"] not in L4.names():
            p.append(f"contain.profile must be one of {', '.join(L4.names())}")
        b = c.get("budget", {})
        if not isinstance(b, dict) or any(k not in ("memory_mb", "pids") for k in b):
            p.append("contain.budget may hold memory_mb and pids only")
        for k in ("agent", "workspace", "sites", "secrets", "profile", "budget"):
            pass
        for k in c:
            if k not in ("agent", "workspace", "sites", "secrets", "profile", "budget"):
                p.append(f"contain.{k}: unknown key at level 5")
        return p

    @staticmethod
    def sentence(doc: dict) -> str:
        c = doc["contain"]
        sites = ", ".join(c.get("sites", [])) or "no sites"
        secrets = ", ".join(c.get("secrets", [])) or "no secrets"
        return f"contain {c['agent']} to {c['workspace']}, {sites}, {secrets}"

    @classmethod
    def compile(cls, doc: dict) -> dict:
        problems = cls.check(doc)
        if problems:
            raise PolicyError("level 5: " + "; ".join(problems))
        c = doc["contain"]
        blanks = {"workspace": c["workspace"]}
        if "sites" in c:
            blanks["sites"] = sorted(set(c["sites"]))
        if "secrets" in c:
            blanks["secrets"] = sorted(set(c["secrets"]))
        for k in ("memory_mb", "pids"):
            if k in c.get("budget", {}):
                blanks[k] = c["budget"][k]
        out = {"pbp": 1, "level": 4, "profile": c.get("profile", DEFAULT_PROFILE), "id": c["agent"], "blanks": blanks}
        return {"document": out, "sentence": cls.sentence(doc)}
