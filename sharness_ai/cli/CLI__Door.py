"""`sharness-ai door conformance NAME`: a door's vectors against a fresh instance of it, the twin
first; a temporary session is made for the run. `NAME` is sharness.fs.disk.twin or sharness.fs.disk."""
import json
import os
import tempfile

from sharness_ai.door import Client
from sharness_ai.door.Conformance import Conformance
from sharness_ai.door.Session import Session, SessionError
from sharness_ai.fs import FS
from sharness_ai.fs.disk import Disk
from sharness_ai.fs.disk.twin import Twin

VECTORS = {"fs": os.path.join(os.path.dirname(os.path.dirname(__file__)), "fs", "vectors", "vectors.json")}


class CLI__Door:
    def __init__(self, main):
        self.main = main

    def cmd_conformance(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        name = args.name.removeprefix("sharness.")
        door_name, _, target = name.partition(".")
        if door_name != "fs" or target not in ("disk", "disk.twin"):
            return m.fail(f"no door called {args.name!r} here", hint="the doors that run: sharness.fs.disk.twin, sharness.fs.disk", code=2)
        with open(VECTORS["fs"], encoding="utf-8") as f:
            spec = json.load(f)
        with tempfile.TemporaryDirectory(prefix="sharness-ai-conformance-") as tmp:
            try:
                session = Session.new(os.path.join(tmp, "session"), ("app", "fs"))
            except SessionError as e:
                return m.fail(str(e), hint="openssl issues the session's certificates", code=2)
            store = Twin() if target == "disk.twin" else Disk(os.path.join(tmp, "root"))
            door = FS(session, store, policy=spec.get("door_policy_for_these_vectors"), port=0)
            port = door.serve(background=True)
            try:
                results = Conformance(Client(session, "app", "fs", port)).run(spec["vectors"])
            finally:
                door.stop()
        summary = Conformance.summary(results)
        m.state.record("conformance", door=args.name, held=summary["held"], of=summary["of"])
        if m.json:
            print(json.dumps({"door": args.name, "mode": store.mode, "results": results, **summary}, indent=1))
            return 0 if not summary["failed"] else 1
        lines = d.head("door conformance", f"{args.name} ({store.mode}): {len(results)} vectors, the twin first")
        for i, r in enumerate(results, 1):
            got = r["got"]
            lines.append(d.row("ok" if r["held"] else "no", f"{i}/{len(results)}", r["name"], f"{got['status'] if isinstance(got, dict) else got}",
                               "" if r["held"] else f"expected {r['expected']}"))
        style = "ok" if not summary["failed"] else "no"
        lines += d.kv("result", f"{d.bar(summary['held'], summary['of'])} {summary['held']}/{summary['of']} held", style=style)
        lines += d.caveat()
        lines += d.kv("next", "sharness-ai door conformance sharness.fs.disk   the same vectors against the real disk" if store.mode == "twin"
                      else "sharness-ai fs serve --target disk --root DIR --session DIR   then the app under a policy with no write right to DIR", style="head")
        t.write(*lines)
        return 0 if not summary["failed"] else 1
