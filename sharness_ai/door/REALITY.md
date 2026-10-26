# REALITY: sharness_ai.door, 26 Oct 2026

- `Session.py`: `Session.new(dir, roles, days)`, `Session.load(dir)`, `EDGES`, `ROLES`, `SessionError`; openssl by subprocess.
- `Door.py`: `Door(session, contract, policy, port)`, `serve(background)`, `stop()`, `dispatch()`, `hello()`; HTTP/1.0, one connection per request.
- `Client.py`: `Client(session, role, callee, port).request(method, path, body)`; `peer_role(sock)`; `context()`.
- `Contract.py`: routes from `ACCEPTS.json` (`{path}` placeholders), both hashes. `Rows.py`: four predicates and the secret shapes.
- `Verdict.py`: `Verdict`, `Audit`. `Conformance.py`: `run(vectors)`, `summary()`.

Not here: the mirror-rule check of an edge's two hashes (the launcher's); a Unix-socket transport with
`SO_PEERCRED`; TLS session resumption; a level served as a door (`POST /v0/compile`); certificate validity under a
day (`-not_after` needs a newer openssl); revocation (a session is short-lived instead). Dependency exceptions
taken: none (openssl is a program on the machine, not a package).
