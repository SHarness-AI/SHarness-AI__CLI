"""Behaviour rows and the closed predicate language a door executes (pbp@sharness's list, the
first four): `append_only`, `max_bytes`, `refuse_secrets`, `within_root` (always on). A row is
`{"resource": "<path prefix>", "op": "write|append|delete|mkdir|*", "where": {...}}`. Anything the
language cannot say is a custom door, not an extension here."""
import re

from sharness_ai.door.Verdict import Verdict

# what a secret looks like on its way into a file: the shapes refused by the site's gate, plus the obvious
SECRET_SHAPES = (
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(rb"sgit_private_vault_"), "a clear vault key"),
    (re.compile(rb"[A-Za-z0-9_-]{20,}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "a vault key"),
    (re.compile(rb"\b(?:sk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{16,}"), "an API token"),
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key id"),
    (re.compile(rb"Bearer\s+[A-Za-z0-9._-]{20,}", re.I), "a bearer token"),
)
PREDICATES = ("append_only", "max_bytes", "refuse_secrets", "within_root")


def _beneath(path: str, prefix: str) -> bool:
    return prefix in ("", "/") or path == prefix or path.startswith(prefix.rstrip("/") + "/")


class Rows:
    def __init__(self, rows: list, defaults: dict = None):
        self.rows = []
        for r in rows:
            where = r.get("where", {})
            bad = [k for k in where if k not in PREDICATES]
            if bad:
                raise ValueError(f"row {r.get('resource')!r}: unknown predicate(s) {bad}; the language is {', '.join(PREDICATES)}")
            self.rows.append({"resource": r.get("resource", "/"), "op": r.get("op", "*"), "where": where})
        self.defaults = {"refuse_secrets": True, "max_bytes": 64 << 20}
        self.defaults.update(defaults or {})

    def for_path(self, path: str, op: str) -> list:
        return [r for r in self.rows if _beneath(path, r["resource"]) and r["op"] in ("*", op)]

    @staticmethod
    def secret_in(data: bytes):
        for rx, what in SECRET_SHAPES:
            if rx.search(data):
                return what
        return None

    def verdict(self, op: str, path: str, data: bytes = b"") -> Verdict:
        """The rows for this path and op, in order; the first refusal wins."""
        rows = self.for_path(path, op)
        where = dict(self.defaults)
        for r in rows:
            where.update(r["where"])
        if op in ("write", "append") and where.get("max_bytes") is not None and len(data) > where["max_bytes"]:
            return Verdict.refuse(f"{len(data)} bytes is over the row's max_bytes {where['max_bytes']}", f"max_bytes {where['max_bytes']} on {path}")
        if op in ("write", "append") and where.get("refuse_secrets"):
            what = self.secret_in(data)
            if what:
                return Verdict.refuse(f"refuses clear secrets: the bytes parse as {what}", "refuse_secrets (every path)")
        if where.get("append_only") and op in ("write", "delete"):
            res = next((r["resource"] for r in rows if r["where"].get("append_only")), path)
            return Verdict.refuse(f"{op} is not append: this path is append_only", f"append_only {res}")
        return Verdict.ok()

    def describe(self) -> list:
        return [{"resource": r["resource"], "op": r["op"], "where": r["where"]} for r in self.rows]
