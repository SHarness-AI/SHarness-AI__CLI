"""The net door: its admin face is the kit's (mutual TLS: hello, policy, log); its working face is
the proxy on a second loopback port, plain HTTP as every client expects a proxy to be, bound to one
uid. The policy's rows: `hosts`, `ports`, `refuse_ip_literals`, `max_connections`."""
import os

from sharness_ai.door import Contract, Door
from sharness_ai.net.Rows import NetRows
from sharness_ai.net.proxy.Proxy import Proxy

HERE = os.path.dirname(__file__)
DEFAULT_POLICY = {"pbp": 1, "id": "sharness.net", "layer": "component", "hosts": [], "ports": [443, 80],
                  "notes": "the door's own policy: the hosts and ports the shell may reach through the proxy"}


class NET(Door):
    role = "net"

    def __init__(self, session, policy: dict = None, port: int = 0, proxy_port: int = 0, allowed_uid: int = None,
                 audit_stream=None):
        policy = policy or dict(DEFAULT_POLICY)
        self.rows = NetRows(policy.get("hosts", []), policy.get("ports", (443, 80)),
                            policy.get("refuse_ip_literals", True), policy.get("max_connections", 64))
        super().__init__(session, Contract(HERE), policy, port=port, audit_stream=audit_stream,
                         targets={"sharness.net.proxy": "live"})
        self.proxy = Proxy(self.rows, self.audit, port=proxy_port, allowed_uid=allowed_uid)

    def hello(self) -> dict:
        h = super().hello()
        h.update({"proxy_port": self.proxy.port, "rows": self.rows.describe(), "allowed_uid": self.proxy.allowed_uid})
        return h

    def start(self):
        """Both faces, in the background. Returns (door_port, proxy_port)."""
        return self.serve(background=True), self.proxy.serve(background=True)

    def stop(self):
        self.proxy.stop()
        super().stop()
