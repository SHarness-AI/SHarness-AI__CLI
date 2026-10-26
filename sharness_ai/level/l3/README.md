# level 3: rows in plain nouns

Accepts the v0 shape with `"level": 3` and `network.sites` (host names; `http://` means port 80; `host:port` names the port). Emits the v0 policy the kernel holds; the host names are reported as unheld rows until `sharness.net` runs; a `connect_tcp_ports` row beside `sites` is a level-1 row passed through and reported. The v0 standard (`policy.py`) is untouched: a level-3 document is compiled, then checked by it.

Status: runnable, proposed (26 Oct 2026). Verb: `sharness-ai policy show|check FILE` reads it; `explain` draws it.
