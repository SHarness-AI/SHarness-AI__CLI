"""Behaviour rows and the closed predicate language a door executes (pbp@sharness's list, the
first four): `append_only`, `max_bytes`, `refuse_secrets`, `within_root` (always on). A row is
`{"resource": "<path prefix>", "op": "write|append|delete|mkdir|*", "where": {...}}`. Anything the
language cannot say is a custom door, not an extension here."""
import re

from sharness_ai.door.Verdict import Verdict

# what a secret looks like on its way into a file: the shapes refused by the site's gate, plus the obvious.
# Every shape is anchored on a literal or a fixed-width field, so a scan is linear in the body: a run such as
# `[A-Za-z0-9_-]{20,}` is never the first thing searched for (the review of 26 Oct 2026 measured the unanchored
# form at 7.8 s on 80 KB; a possessive run alone still restarts at every position).
UUID = rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
SECRET_SHAPES = (
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key"),
    (re.compile(rb"sgit_private_vault_"), "a clear vault key"),
    (re.compile(rb":" + UUID), "a vault key"),                   # checked further below: 20 run characters before the colon
    (re.compile(rb"\b(?:sk|ghp|gho|xox[baprs])[-_][A-Za-z0-9_-]{16,}"), "an API token"),
    (re.compile(rb"\bAKIA[0-9A-Z]{16}\b"), "an AWS access key id"),
    (re.compile(rb"Bearer\s+[A-Za-z0-9._-]{20,}", re.I), "a bearer token"),
)
RUN = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
HARD_CAP = 64 << 20            # no row and no policy can lift this; the door never holds more in memory
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
        self.defaults = {"refuse_secrets": True, "max_bytes": HARD_CAP}
        for k, v in (defaults or {}).items():
            if k == "max_bytes" and isinstance(v, int) and not isinstance(v, bool) and 0 < v <= HARD_CAP:
                self.defaults[k] = v                     # a policy may lower the cap, never lift it
            elif k not in ("max_bytes", "refuse_secrets") and k in PREDICATES:
                self.defaults[k] = v                     # refuse_secrets cannot be switched off: the contract says always

    def for_path(self, path: str, op: str) -> list:
        return [r for r in self.rows if _beneath(path, r["resource"]) and r["op"] in ("*", op)]

    @staticmethod
    def secret_in(data: bytes):
        for rx, what in SECRET_SHAPES:
            for m in rx.finditer(data):
                if what != "a vault key":
                    return what
                start = m.start()                               # the colon: a vault key has a 20+ run before it
                if start >= 20 and all(b in RUN for b in data[start - 20:start]):
                    return what
        return None

    def verdict(self, op: str, path: str, data: bytes = b"") -> Verdict:
        """The rows for this path and op, in order; the first refusal wins."""
        rows = self.for_path(path, op)
        where = dict(self.defaults)
        for r in rows:
            for k, v in r["where"].items():
                if k == "max_bytes":
                    if isinstance(v, int) and not isinstance(v, bool) and 0 < v < where["max_bytes"]:
                        where[k] = v                      # a row may lower the cap, never lift it
                elif k != "refuse_secrets":               # always on, whatever a row says
                    where[k] = v
        if op in ("write", "append") and len(data) > where["max_bytes"]:
            return Verdict.refuse(f"{len(data)} bytes is over the row's max_bytes {where['max_bytes']}", f"max_bytes {where['max_bytes']} on {path}")
        if op in ("write", "append"):
            what = self.secret_in(data)
            if what:
                return Verdict.refuse(f"refuses clear secrets: the bytes parse as {what}", "refuse_secrets (every path)")
        if where.get("append_only") and op in ("write", "delete"):
            res = next((r["resource"] for r in rows if r["where"].get("append_only")), path)
            return Verdict.refuse(f"{op} is not append: this path is append_only", f"append_only {res}")
        return Verdict.ok()

    def describe(self) -> list:
        return [{"resource": r["resource"], "op": r["op"], "where": r["where"]} for r in self.rows]
