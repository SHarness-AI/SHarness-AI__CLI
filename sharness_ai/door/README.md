# sharness_ai.door: the door kit

What every door and every level service shares, written once, standard library only.

| Piece | Role |
|---|---|
| `Session` | E05: a session CA and one certificate per role by `openssl` (P-256, TLS 1.3, SAN URI `spiffe://<session>/<role>`, DNS localhost, CA pathlen 0); the CA key is destroyed after issuing. The edge matrix `EDGES`. |
| `Door` | the service: loopback, mutual TLS from the session, the peer's role from its certificate, the edge checked, the contract matched, `GET /v0/hello`, `/v0/policy`, `/v0/log` on every door, then `handle()` |
| `Client` | a caller: the callee's role checked from its certificate before the first byte of the request |
| `Contract` | `ACCEPTS.json` and `EMITS.json` loaded and hashed; a request outside the routes is `404 not in what this door accepts` |
| `Rows` | the behaviour rows and the closed predicate language: `within_root`, `refuse_secrets`, `max_bytes`, `append_only` |
| `Verdict`, `Audit` | allow or deny with the row that decided; one line per request, never a body or a secret |
| `Conformance` | a door's vectors against a running instance: held, failed, like `hello` |

**Status: runnable, proposed (26 Oct 2026).** Measured here: a loopback mutual-TLS request about 7 to 8 ms
end to end including context setup, Python 3.13, 26 Oct 2026. A door is a Boundary for its caller only once
the launcher (not built) gives it its own uid and closes every other path; until then a Setting.
