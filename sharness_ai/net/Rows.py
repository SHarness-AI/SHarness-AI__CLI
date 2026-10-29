"""The network door's rows: which hosts (exact, or `*.suffix`), which ports, no IP literals.
Capability rows at level 3 (`sites`) land here as the allowlist; the kernel holds the port to the
proxy, the proxy holds the host. Closed: anything finer (a method, a path) is `net.http`, a door
below this one, not written."""
import ipaddress
import re

from sharness_ai.door.Verdict import Verdict

HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NetRows:
    def __init__(self, hosts: list, ports=(443, 80), refuse_ip_literals: bool = True, max_connections: int = 64):
        self.exact, self.suffixes = set(), set()
        for h in hosts:
            h = str(h).strip().lower()
            if h.startswith("*."):
                self.suffixes.add(h[2:])
            elif h:
                self.exact.add(h)
        self.ports = {int(p) for p in ports}
        self.refuse_ip_literals = refuse_ip_literals
        self.max_connections = max_connections

    def allow(self, host: str, port: int) -> Verdict:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return Verdict.refuse("no host", "hosts")
        try:
            ipaddress.ip_address(host.strip("[]"))
            if self.refuse_ip_literals:
                return Verdict.refuse(f"{host}: IP literals are refused; name the host", "refuse_ip_literals")
        except ValueError:
            if not HOST.match(host):
                return Verdict.refuse(f"{host!r} is not a host name", "hosts")
        if port not in self.ports:
            return Verdict.refuse(f"port {port} is not on the list {sorted(self.ports)}", f"ports {sorted(self.ports)}")
        if host in self.exact or any(host == s or host.endswith("." + s) for s in self.suffixes):
            return Verdict.ok()
        return Verdict.refuse(f"{host} is not on the allowlist", f"hosts {sorted(self.exact | {'*.' + s for s in self.suffixes})}")

    def describe(self) -> dict:
        return {"hosts": sorted(self.exact | {"*." + s for s in self.suffixes}), "ports": sorted(self.ports),
                "refuse_ip_literals": self.refuse_ip_literals, "max_connections": self.max_connections}
