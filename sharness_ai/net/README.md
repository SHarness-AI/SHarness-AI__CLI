# sharness.net: the only network client

The door for the network. Two faces: the kit's admin face under mutual TLS (`hello`, `policy`, `log`) and the
proxy face, `sharness.net.proxy`, a plain HTTP proxy on loopback bound to one uid, which is what every client
expects `HTTPS_PROXY` to be. A shell under the launcher has no network but this proxy's port (the kernel holds
that row), so every connection it makes is a host and a port the door decided.

| Rule | Verdict |
|---|---|
| a host off the allowlist (`hosts`: exact or `*.suffix`) | `403 hosts` |
| an IP literal | `403 refuse_ip_literals` |
| a port off the list (`ports`, default 443 and 80) | `403 ports` |
| a tunnel whose TLS hello names another host than the CONNECT | cut: `no domain fronting` |
| a caller that is not the shell's uid | `403 one uid per proxy` |
| more than `max_connections` open | `403` |

`sharness-ai net serve --hosts github.com pypi.org --session DIR`; `net hello`; `net log` (launcher).

**Status: runnable, proposed (26 Oct 2026).** The proxy does not terminate TLS (bytes pass; SNI is checked),
so it holds hosts and ports, not paths: that is `net.http`, a door below this one, not written. UDP is not its
to hold; a shell that resolves names itself leaks DNS unless the launcher gives it no UDP. Standard library only.
