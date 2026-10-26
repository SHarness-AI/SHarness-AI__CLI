"""What a door accepts: a closed list of routes, read from its ACCEPTS.json and hashed. A request
that matches no route is refused before any row is read (`404 not in what this door accepts`).
EMITS.json is read and hashed the same way; the launcher compares the two hashes on an edge (the
mirror rule), which is not done here yet."""
import json
import os
import re

from sharness_ai.policy import policy_hash


class Contract:
    def __init__(self, directory: str):
        self.dir = directory
        self.accepts = self._load("ACCEPTS.json")
        self.emits = self._load("EMITS.json")
        self.accepts_hash = policy_hash(self.accepts)
        self.emits_hash = policy_hash(self.emits)
        self.routes = [(r["method"], re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>.+)", r["path"]) + "$"), r)
                       for r in self.accepts.get("routes", [])]

    def _load(self, name: str) -> dict:
        with open(os.path.join(self.dir, name), encoding="utf-8") as f:
            return json.load(f)

    def match(self, method: str, path: str):
        """(route, params) for the first route that accepts this request, or (None, None)."""
        for m, rx, route in self.routes:
            if m == method:
                hit = rx.match(path)
                if hit:
                    return route, hit.groupdict()
        return None, None

    def describe(self) -> dict:
        return {"door": self.accepts.get("door"), "accepts": self.accepts_hash, "emits": self.emits_hash,
                "routes": [f"{r['method']} {r['path']}" for r in self.accepts.get("routes", [])]}
