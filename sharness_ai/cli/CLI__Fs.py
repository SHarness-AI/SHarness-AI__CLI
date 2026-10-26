"""`sharness-ai fs`: the first door. `serve` runs it (disk or disk.twin); `hello`, `put`, `get`,
`append`, `rm`, `ls`, `log` call it as the app. Every verdict names who refused and the row."""
import json
import sys
import threading

from sharness_ai.door import Client
from sharness_ai.door.Client import DoorError
from sharness_ai.door.Session import Session, SessionError
from sharness_ai.fs import FS
from sharness_ai.fs.disk import Disk
from sharness_ai.fs.disk.twin import Twin
from sharness_ai.policy import PolicyError, load

DEFAULT_PORT = 7301


class CLI__Fs:
    def __init__(self, main):
        self.main = main

    def _session(self, args):
        try:
            return Session.load(args.session)
        except SessionError as e:
            self.main.fail(str(e), hint=f"sharness-ai session new --dir {args.session} --roles app fs", code=2)
            return None

    def build(self, args):
        """The door object for `serve`, or None after a failure message."""
        s = self._session(args)
        if s is None:
            return None
        policy = None
        if args.policy:
            try:
                policy = load(args.policy)
            except (PolicyError, OSError) as e:
                self.main.fail(f"door policy: {e}", code=2)
                return None
        store = Twin() if args.target == "disk.twin" else Disk(args.root)
        try:
            return FS(s, store, policy=policy, port=args.port, audit_stream=sys.stderr if args.audit else None)
        except ValueError as e:
            self.main.fail(str(e), code=2)
            return None

    def cmd_serve(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        door = self.build(args)
        if door is None:
            return 2
        port = door.serve(background=True)
        m.state.record("door", name=f"sharness.fs.{args.target}", port=port, session=args.session)
        lines = d.head("fs serve", f"sharness.fs.{args.target} is listening")
        lines += d.kv("door", f"sharness.fs.{args.target}  {door.session.spiffe('fs')}  127.0.0.1:{port}  mode {door.store.mode}", style="bold")
        if args.target == "disk":
            lines += d.kv("root", door.store.root)
        lines += d.kv("rows", "; ".join(f"{r['resource']} {r['op']} {r['where']}" for r in door.rows.describe())
                      or "the always-on rows only: within_root, refuse_secrets, max_bytes 64 MiB")
        lines += d.kv("accepts", f"{door.contract.accepts_hash}   {len(door.contract.routes)} routes", style="dim")
        lines += d.caveat()
        lines += d.kv("try", f"sharness-ai fs hello --session {args.session} --port {port}", style="head")
        t.write(*lines)
        if args.once:
            door.stop()
            return 0
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            door.stop()
            t.write("stopped.")
        return 0

    def _call(self, args, method, path, body=None) -> int:
        m = self.main
        s = self._session(args)
        if s is None:
            return 2
        try:
            status, data = Client(s, "app", "fs", args.port).request(method, path, body)
        except DoorError as e:
            return m.fail(str(e), hint=f"is a door running? sharness-ai fs serve --session {args.session} --port {args.port}", code=2)
        if m.json:
            print(json.dumps({"status": status, "response": data}, indent=1))
            return 0 if status < 400 else 1
        t, d = m.term, m.draw
        allowed = status < 400
        who = "allowed by sharness.fs" if allowed else f"refused by sharness.fs ({status})"
        note = (data.get("reason", "") + (f"  row: {data['row']}" if data.get("row") else "")) if isinstance(data, dict) else str(data)
        t.write(d.row("ok" if allowed else "no", method.lower(), path.replace("/v0/files/", "") or "/", who, note))
        if isinstance(data, dict):
            if "content" in data:
                t.write(data["content"].rstrip("\n"))
            if path == "/v0/hello":
                t.write(*d.kv("targets", ", ".join(f"{k} ({v})" for k, v in data.get("targets", {}).items())))
                t.write(*d.kv("hashes", f"accepts {d.hash_short(data.get('accepts', ''))}  emits {d.hash_short(data.get('emits', ''))}  policy {d.hash_short(data.get('policy', ''))}", style="dim"))
                t.write(*d.kv("caveat", data.get("caveat", ""), style="dim"))
            for f in data.get("files", []):
                t.write(f"    {f}")
            for line in data.get("lines", []):
                t.write(f"    {line['at']} {line['peer']} {line['method']} {line['path']} {'allowed' if line['allowed'] else 'refused'} {line.get('reason', '')}")
        return 0 if allowed else 1

    @staticmethod
    def _bytes(source):
        if source and source != "-":
            with open(source, "rb") as f:
                return f.read()
        return sys.stdin.buffer.read()

    def cmd_hello(self, args) -> int:
        return self._call(args, "GET", "/v0/hello")

    def cmd_put(self, args) -> int:
        return self._call(args, "PUT", f"/v0/files/{args.path}", self._bytes(args.source))

    def cmd_append(self, args) -> int:
        return self._call(args, "POST", f"/v0/files/{args.path}/append", self._bytes(args.source))

    def cmd_get(self, args) -> int:
        return self._call(args, "GET", f"/v0/files/{args.path}")

    def cmd_rm(self, args) -> int:
        return self._call(args, "DELETE", f"/v0/files/{args.path}")

    def cmd_ls(self, args) -> int:
        return self._call(args, "GET", "/v0/files")

    def cmd_log(self, args) -> int:
        return self._call(args, "GET", "/v0/log")
