"""`sharness-ai session new|show`: E05 as a verb. One CA, one certificate per role, the CA key
destroyed; what every door and every caller loads."""
import json
import os

from sharness_ai.door.Session import EDGES, ROLES, Session, SessionError


class CLI__Session:
    def __init__(self, main):
        self.main = main

    def cmd_new(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        roles = tuple(args.roles or ("app", "fs"))
        try:
            s = Session.new(args.dir, roles, days=args.days)
        except SessionError as e:
            return m.fail(str(e), hint="openssl issues the certificates; nothing else is needed", code=2)
        m.state.record("session", dir=os.path.abspath(args.dir), id=s.id, roles=list(roles))
        edges = sorted(f"{a}->{b}" for a, b in EDGES if a in roles and b in roles)
        if m.json:
            print(json.dumps({"dir": s.dir, "id": s.id, "roles": list(roles), "edges": edges}, indent=1))
            return 0
        lines = d.head("session new", "a session CA and one identity per role, by openssl; the CA key is gone")
        lines += d.kv("session", f"{s.id}   {s.dir}", style="bold")
        lines += d.kv("roles", "  ".join(f"{r} {t.glyph('arrow')} {s.spiffe(r)}" for r in roles))
        lines += d.kv("edges", ", ".join(edges) or "none between these roles")
        lines += d.kv("validity", f"{args.days} day(s); TLS 1.3, P-256; both sides check the other's role on every connection", style="dim")
        lines += d.kv("next", f"sharness-ai fs serve --target disk.twin --session {args.dir}", style="head")
        t.write(*lines)
        return 0

    def cmd_show(self, args) -> int:
        m = self.main
        try:
            s = Session.load(args.dir)
        except SessionError as e:
            return m.fail(str(e), code=2)
        if m.json:
            print(json.dumps({"dir": s.dir, "id": s.id, "roles": list(s.roles), "created": s.created}, indent=1))
            return 0
        d = m.draw
        lines = d.head("session", f"{s.id} in {s.dir}, created {s.created}")
        for r in s.roles:
            lines += d.kv(r, f"{s.spiffe(r)}   {s.cert(r)}")
        lines += d.kv("roles known", ", ".join(ROLES), style="dim")
        m.term.write(*lines)
        return 0
