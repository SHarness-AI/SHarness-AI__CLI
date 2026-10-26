"""Level 4: a profile and its blanks, compiled to rows in plain nouns (level 3).

A profile is a level-3 template a vendor ships beside a tool: the rows a role needs, with blanks
(`$workspace`, `$sites`, `$secrets`, `$memory_mb`, `$pids`) the person fills. The six here are the
example policies P0 to P5 as templates, `profiles/<name>.json`. A level-4 document names the
profile and fills the blanks: `{"pbp": 1, "level": 4, "profile": "coding-agent", "blanks":
{"workspace": "/abs/path", "sites": ["github.com"]}}`. Compilation is substitution and nothing
else, so two people who fill the same blanks the same way get the same level-3 document and hash."""
import json
import os
from pathlib import Path

from sharness_ai.policy import PolicyError

PROFILES = Path(__file__).resolve().parent / "profiles"
LEVEL = 4
BLANKS = ("workspace", "sites", "secrets", "memory_mb", "pids")


class L4:
    level = LEVEL
    emits = 3

    @staticmethod
    def names() -> list:
        return sorted(p.stem for p in PROFILES.glob("*.json"))

    @classmethod
    def load(cls, name: str) -> dict:
        path = PROFILES / f"{name}.json"
        if not path.is_file() or "/" in name or name.startswith("."):
            raise PolicyError(f"no profile called {name!r}; the profiles are {', '.join(cls.names())}")
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    @classmethod
    def check(cls, doc: dict) -> list:
        p = []
        if doc.get("level") != LEVEL:
            p.append(f"level must be {LEVEL}")
        name = doc.get("profile")
        if not isinstance(name, str) or name not in cls.names():
            p.append(f"profile must be one of {', '.join(cls.names())}")
        blanks = doc.get("blanks", {})
        if not isinstance(blanks, dict):
            p.append("blanks must be an object")
            return p
        for k in blanks:
            if k not in BLANKS:
                p.append(f"blanks.{k}: unknown blank; the blanks are {', '.join(BLANKS)}")
        ws = blanks.get("workspace")
        if ws is not None and (not isinstance(ws, str) or not ws.startswith("/") or os.path.normpath(ws) != ws):
            p.append("blanks.workspace must be an absolute, normalised path")
        for k in ("sites", "secrets"):
            if k in blanks and (not isinstance(blanks[k], list) or not all(isinstance(x, str) for x in blanks[k])):
                p.append(f"blanks.{k} must be a list of strings")
        for k in ("memory_mb", "pids"):
            if k in blanks and (isinstance(blanks[k], bool) or not isinstance(blanks[k], int) or blanks[k] < 0):
                p.append(f"blanks.{k} must be a non-negative integer")
        return p

    @staticmethod
    def _fill(node, blanks: dict):
        """Replace `$name` tokens. A token that is a whole list element splices the list."""
        if isinstance(node, str) and node.startswith("$"):
            name, _, rest = node[1:].partition("/")
            value = blanks[name]
            return f"{value}/{rest}" if rest and isinstance(value, str) else value
        if isinstance(node, list):
            out = []
            for x in node:
                v = L4._fill(x, blanks)
                if isinstance(x, str) and x.startswith("$") and isinstance(v, list):
                    out.extend(v)
                else:
                    out.append(v)
            return out
        if isinstance(node, dict):
            return {k: L4._fill(v, blanks) for k, v in node.items()}
        return node

    @classmethod
    def compile(cls, doc: dict) -> dict:
        problems = cls.check(doc)
        if problems:
            raise PolicyError("level 4: " + "; ".join(problems))
        profile = cls.load(doc["profile"])
        blanks = dict(profile.get("blanks", {}))
        blanks.update(doc.get("blanks", {}))
        missing = [k for k in BLANKS if blanks.get(k) is None]
        if missing:
            raise PolicyError(f"level 4: the profile {doc['profile']!r} leaves {', '.join(missing)} blank and the document does not fill them")
        template = profile["template"]
        out = cls._fill(template, blanks)
        out["level"] = 3
        out["id"] = doc.get("id") or profile.get("id") or doc["profile"]
        # dedupe and sort the path lists so the same blanks always give the same bytes
        for k in ("read", "write", "exec"):
            if isinstance(out.get("files", {}).get(k), list):
                out["files"][k] = sorted(set(out["files"][k]))
        if isinstance(out.get("network"), dict) and isinstance(out["network"].get("sites"), list):
            out["network"]["sites"] = sorted(set(out["network"]["sites"]))
        if isinstance(out.get("network"), dict) and not out["network"].get("sites") and not out["network"].get("connect_tcp_ports"):
            out["network"] = "none"
        if not blanks.get("secrets"):
            out.pop("secrets", None)
        for k in ("max_memory_mb", "max_pids"):
            if out.get("process", {}).get(k) == 0:
                out["process"].pop(k)
        return {"document": out, "profile": profile, "blanks": blanks}
