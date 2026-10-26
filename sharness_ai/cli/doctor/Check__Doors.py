"""Do the doors load and answer? The fs twin and the net door are started on free ports with a
throwaway session, asked hello, and stopped: the whole kit in one check, a few hundred ms."""
import os
import tempfile
import time

from sharness_ai.cli.doctor.Check__Result import PASS, SKIP, WARN, Check__Result


class Check__Doors:
    def execute(self, ctx) -> Check__Result:
        t0 = time.monotonic()
        r = Check__Result("doors")
        from sharness_ai.door.Session import Session, SessionError, openssl
        try:
            openssl()
        except SessionError:
            r.status, r.message = SKIP, "no openssl: no session, so no door to ask"
            return r.done(t0)
        from sharness_ai.door import Client
        from sharness_ai.fs import FS
        from sharness_ai.fs.disk.twin import Twin
        from sharness_ai.net import NET
        with tempfile.TemporaryDirectory(prefix="sharness-ai-doctor-doors-") as d:
            try:
                s = Session.new(os.path.join(d, "s"), ("app", "fs", "net", "launcher"))
                fs = FS(s, Twin())
                net = NET(s, policy={"pbp": 1, "id": "sharness.net", "hosts": ["localhost"], "ports": [443]})
                fs_port = fs.serve(background=True)
                net_port, proxy_port = net.start()
                try:
                    a = Client(s, "app", "fs", fs_port).request("GET", "/v0/hello")[1]
                    b = Client(s, "app", "net", net_port).request("GET", "/v0/hello")[1]
                finally:
                    fs.stop()
                    net.stop()
            except Exception as e:  # noqa: BLE001 - one check, one line
                r.status, r.message = WARN, f"a door did not answer: {type(e).__name__}: {e}"
                r.hint = "sharness-ai door conformance sharness.fs.disk.twin shows which request fails"
                return r.done(t0)
        r.status = PASS
        r.message = (f"sharness.fs ({', '.join(a.get('targets', {}))}) and sharness.net (proxy port {b.get('proxy_port')}) answer hello "
                     f"over mutual TLS; a Setting until the launcher")
        return r.done(t0)
