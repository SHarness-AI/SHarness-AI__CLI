"""The fs door's logic, the same over any Store: normalise the path, keep it under the root,
ask the rows, then send to the target. Content is never interpreted beyond what it parses as."""
import os
import posixpath

from sharness_ai.door import Contract, Door, Rows, Verdict
from sharness_ai.fs.Store import OutsideRoot, Store

HERE = os.path.dirname(__file__)
DEFAULT_POLICY = {"pbp": 1, "id": "sharness.fs", "layer": "component", "rows": [],
                  "notes": "the door's own policy: rows for the app's writes; the kernel half is the app's policy"}


class FS(Door):
    role = "fs"

    def __init__(self, session, store: Store, policy: dict = None, port: int = 0, audit_stream=None, target: str = "disk"):
        policy = policy or dict(DEFAULT_POLICY)
        self.store = store
        self.rows = Rows(policy.get("rows", []), policy.get("defaults"))
        name = f"{target}.twin" if store.mode == "twin" else target
        super().__init__(session, Contract(HERE), policy, port=port, audit_stream=audit_stream, targets={f"sharness.fs.{name}": store.mode})

    @staticmethod
    def normalise(raw: str):
        """A relative path inside the root, or None: no `..`, no absolute, no empty, no control chars."""
        if not raw or any(ord(c) < 32 for c in raw) or raw.startswith("/"):
            return None
        parts = raw.split("/")
        if ".." in parts:
            return None
        p = posixpath.normpath("/" + raw)
        if p == "/" or p.startswith("/.."):
            return None
        return p.lstrip("/")

    def handle(self, request: dict) -> Verdict:
        route, params, body = request["route"], request["params"], request["body"]
        op = route["op"]
        if op == "mkdir":
            try:
                raw = __import__("json").loads(body or b"{}").get("path", "")
            except ValueError:
                return Verdict.refuse("mkdir wants {\"path\": …}", status=400)
        else:
            raw = params.get("path", "")
        if op == "list":
            return Verdict.ok(files=self.store.listing())
        rel = self.normalise(raw)
        if rel is None:
            return Verdict.refuse(f"{raw!r} is outside the root or not a path", "within_root (every path)")
        v = self.rows.verdict(op, "/" + rel, body)
        if not v.allowed:
            return v
        try:
            if op == "read":
                if not self.store.exists(rel):
                    return Verdict.refuse("no such file", status=404)
                data = self.store.read(rel)
                return Verdict.ok(path=rel, size=len(data), content=data.decode("utf-8", "replace"))
            if op == "write":
                self.store.write(rel, body)
                return Verdict.ok(201, path=rel, size=len(body))
            if op == "append":
                self.store.append(rel, body)
                return Verdict.ok(201, path=rel, appended=len(body))
            if op == "delete":
                if not self.store.exists(rel):
                    return Verdict.refuse("no such file", status=404)
                self.store.delete(rel)
                return Verdict.ok(204, path=rel)
            if op == "mkdir":
                self.store.mkdir(rel)
                return Verdict.ok(201, path=rel)
            if op == "list":
                return Verdict.ok(files=self.store.listing())
        except OutsideRoot as e:
            return Verdict.refuse(f"symlink escape: {e}", "within_root (every path)")
        except OSError as e:
            return Verdict.refuse(f"the target refused: {e.strerror or e}", status=502)
        return Verdict.refuse(f"no such op {op}", status=501)
