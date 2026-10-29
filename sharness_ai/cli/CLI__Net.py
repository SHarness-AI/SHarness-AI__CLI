"""`sharness-ai net serve|hello|log`: the network door and its proxy, on their own (without the
shell launcher), so a person can point any program's HTTPS_PROXY at it and watch the verdicts."""
import json
import sys
import threading

from sharness_ai.door import Client
from sharness_ai.door.Client import DoorError
from sharness_ai.door.Session import Session, SessionError
from sharness_ai.net import NET

DEFAULT_PORT, DEFAULT_PROXY_PORT = 7302, 3128


class CLI__Net:
    def __init__(self, main):
        self.main = main

    def _session(self, args):
        try:
            return Session.load(args.session)
        except SessionError as e:
            self.main.fail(str(e), hint=f"sharness-ai session new --dir {args.session} --roles app fs net launcher", code=2)
            return None

    def cmd_serve(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        s = self._session(args)
        if s is None:
            return 2
        policy = {"pbp": 1, "id": "sharness.net", "layer": "component", "hosts": args.hosts or [], "ports": args.ports or [443, 80]}
        door = NET(s, policy=policy, port=args.port, proxy_port=args.proxy_port, allowed_uid=args.uid,
                   audit_stream=sys.stderr if args.audit else None)
        door_port, proxy_port = door.start()
        m.state.record("door", name="sharness.net.proxy", port=door_port, proxy_port=proxy_port, session=args.session)
        lines = d.head("net serve", "sharness.net.proxy is listening")
        lines += d.kv("door", f"sharness.net  {s.spiffe('net')}  127.0.0.1:{door_port} (mutual TLS)", style="bold")
        lines += d.kv("proxy", f"http://127.0.0.1:{proxy_port}   HTTPS_PROXY for any program" + (f", uid {args.uid} only" if args.uid is not None else ", any local uid"), style="bold")
        lines += d.kv("hosts", " ".join(door.rows.describe()["hosts"]) or "none: every host is refused until --hosts names one")
        lines += d.kv("ports", " ".join(map(str, door.rows.describe()["ports"])) + "  IP literals refused; a tunnel's SNI must match its host")
        lines += d.caveat()
        lines += d.kv("try", f"HTTPS_PROXY=http://127.0.0.1:{proxy_port} curl -sI https://{(args.hosts or ['github.com'])[0]} | head -1", style="head")
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

    def _call(self, args, role, path) -> int:
        m = self.main
        s = self._session(args)
        if s is None:
            return 2
        try:
            status, data = Client(s, role, "net", args.port).request("GET", path)
        except DoorError as e:
            return m.fail(str(e), hint=f"is the door running? sharness-ai net serve --session {args.session} --port {args.port}", code=2)
        if m.json:
            print(json.dumps({"status": status, "response": data}, indent=1))
            return 0 if status < 400 else 1
        t, d = m.term, m.draw
        if path == "/v0/hello" and isinstance(data, dict) and status == 200:
            t.write(d.row("ok", "get", "/v0/hello", "allowed by sharness.net"))
            t.write(*d.kv("proxy", f"127.0.0.1:{data.get('proxy_port')}  uid {data.get('allowed_uid')}  hosts {' '.join(data.get('rows', {}).get('hosts', [])) or 'none'}"))
            t.write(*d.kv("caveat", data.get("caveat", ""), style="dim"))
            return 0
        if path == "/v0/log" and isinstance(data, dict) and status == 200:
            for line in data.get("lines", []):
                t.write(d.row("ok" if line["allowed"] else "no", line["method"].lower(), line["path"], "allowed" if line["allowed"] else f"refused: {line.get('reason', '')}", line.get("row", "")))
            return 0
        t.write(d.row("no", "get", path, f"refused ({status})", data.get("reason", "") if isinstance(data, dict) else str(data)))
        return 1

    def cmd_hello(self, args) -> int:
        return self._call(args, "app", "/v0/hello")

    def cmd_log(self, args) -> int:
        return self._call(args, "launcher", "/v0/log")
