# REALITY: sharness.net, 26 Oct 2026

- `NET.py`: the door (admin face: hello with the proxy port and the rows; policy; log for the launcher). `start()` runs both faces.
- `Rows.py`: `NetRows(hosts, ports, refuse_ip_literals, max_connections).allow(host, port)`.
- `proxy/Proxy.py`: CONNECT tunnels with the SNI check, absolute-URL forwarding once, the peer uid from `/proc/net/tcp`,
  one audit line per request, 30 s connect timeout, 300 s idle, 16 KiB request head.

Not here: TLS termination (`net` as the TLS client inside the tunnel, which needs a per-host certificate the shell
trusts), `POST /v0/fetch` (the harness-aware mode), `net.direct` (the kernel's socket as a named target) and
`net.direct.twin` (record and replay), `net.http` (methods and paths), conformance vectors, HTTP/2, a hostname
resolved by the proxy for the shell (the shell's own resolver is UDP the kernel does not see). Dependency exceptions
taken: none.
