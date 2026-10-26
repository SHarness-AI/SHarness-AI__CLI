"""The door kit: what every door and every level service shares, written once (standard library).

A door is a process that holds one resource's behaviour rows: a small HTTP/1.1 API on loopback
under mutual TLS 1.3 from a session CA, the peer's role read from its certificate's SPIFFE URI,
the edge (caller, callee) checked on both sides, one JSON request in, one verdict out, an audit
line per request that never carries a secret. Session issues the identities with `openssl` (no
dependency; the CA key is deleted after issuing). Contract is the closed list of routes a door
accepts, hashed. Rows holds the behaviour rows and the closed predicate language. Conformance
runs a door's vectors against a running instance. Design: sharness.ai/design/pbp §6 and the
brief "the mashup in code". Status: runnable, proposed (26 Oct 2026); a door is a Boundary for
the app only once the launcher (not built) gives it its own uid and closes every other path.
"""
from sharness_ai.door.Client import Client
from sharness_ai.door.Contract import Contract
from sharness_ai.door.Door import Door
from sharness_ai.door.Rows import Rows
from sharness_ai.door.Session import EDGES, Session
from sharness_ai.door.Verdict import Audit, Verdict

__all__ = ["Audit", "Client", "Contract", "Door", "EDGES", "Rows", "Session", "Verdict"]
