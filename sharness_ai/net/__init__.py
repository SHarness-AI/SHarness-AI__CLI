"""sharness.net: the only network client. The door alone is the API (hosts, ports, endpoints);
every leaf names where it sends. `net.proxy` is the first target: an HTTP proxy on loopback that
tunnels CONNECT and forwards plain HTTP for one uid, under a host allowlist, refusing IP literals
and ports off the list, one audit line per request. The shell launcher gives a shell no network
but this proxy's port, so every connection the shell makes is a row the door decided.
Standard library only. Status: runnable, proposed (26 Oct 2026). What it does not do is in
REALITY.md: it does not terminate TLS (the tunnel's bytes pass; SNI is checked against the
CONNECT host), it has no twin yet, and UDP is not its to hold."""
from sharness_ai.net.NET import NET
from sharness_ai.net.Rows import NetRows

__all__ = ["NET", "NetRows"]
