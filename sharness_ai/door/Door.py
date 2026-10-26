"""The service every door is: loopback, mutual TLS 1.3 from the session, the peer's role from its
certificate, the edge checked, the contract matched, then `handle()` (the door's own rows), one
audit line per request. Subclasses set `role`, give a Contract and implement handle()."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sharness_ai.door.Client import context, peer_role
from sharness_ai.door.Contract import Contract
from sharness_ai.door.Session import EDGES, Session
from sharness_ai.door.Verdict import Audit, Verdict
from sharness_ai.policy import policy_hash

MAX_BODY = 64 << 20


class Door:
    role = "door"

    def __init__(self, session: Session, contract: Contract, policy: dict, port: int = 0, host: str = "127.0.0.1",
                 audit_stream=None, targets: dict = None):
        self.session, self.contract, self.policy = session, contract, policy
        self.host, self.port = host, port
        self.audit = Audit(f"sharness.{self.role}", stream=audit_stream)
        self.targets = targets or {}                 # name -> "twin" | "live"
        self.server = None

    # ---- what every door answers ------------------------------------------------------------------
    def hello(self) -> dict:
        return {"door": f"sharness.{self.role}", "spiffe": self.session.spiffe(self.role), "targets": self.targets,
                "accepts": self.contract.accepts_hash, "emits": self.contract.emits_hash, "policy": policy_hash(self.policy),
                "caveat": "a Boundary for the caller only once the launcher gives this door its own uid and closes every other path; until then a Setting"}

    def handle(self, request: dict) -> Verdict:            # the door's rows; subclasses implement
        return Verdict.refuse("this door holds no rows", status=501)

    def dispatch(self, peer: str, method: str, path: str, body: bytes) -> Verdict:
        if (peer, self.role) not in EDGES:
            return Verdict.refuse(f"edge {peer or '?'}->{self.role} is not in the manifest", "the edge matrix")
        if method == "GET" and path == "/v0/hello":
            return Verdict.ok(**self.hello())
        if method == "GET" and path == "/v0/policy":
            return Verdict.ok(policy=self.policy, hash=policy_hash(self.policy), contract=self.contract.describe())
        if method == "GET" and path == "/v0/log":
            if peer != "launcher":
                return Verdict.refuse("the log is the launcher's to read; a caller sees only its own verdicts", "the edge matrix")
            return Verdict.ok(lines=self.audit.dump())
        route, params = self.contract.match(method, path)
        if route is None:
            return Verdict.refuse(f"{method} {path} is not in what this door accepts", "ACCEPTS.json", status=404)
        return self.handle({"method": method, "path": path, "params": params, "body": body, "peer": peer, "route": route})

    # ---- serving ------------------------------------------------------------------------------------
    def serve(self, background: bool = False) -> int:
        door = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"                 # one connection per request, as the design says
            server_version = "sharness-ai"
            timeout = 30                                  # a caller that stalls does not hold a thread for ever
            disable_nagle_algorithm = True                # TCP_NODELAY: the design's 3.2 ms, not 46 (Architecture)

            def setup(self):
                """The TLS handshake happens here, in this connection's own thread and under the timeout, so
                an idle or hostile TCP connection never holds the accept loop; a failed handshake raises and
                handle_error writes the audit line."""
                self.request.settimeout(self.timeout)
                self.request = door.ctx.wrap_socket(self.request, server_side=True)
                super().setup()

            def _answer(self, v):
                out = json.dumps(v.payload()).encode()
                self.send_response(v.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def _do(self):
                peer = peer_role(self.connection)
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                    if n < 0:
                        raise ValueError
                except ValueError:
                    v = Verdict.refuse("Content-Length is not a number", status=400)
                    door.audit.record(peer, self.command, self.path, 0, v)
                    self._answer(v)
                    return
                if (peer, door.role) not in EDGES:            # the edge, before a single byte of body is read
                    v = Verdict.refuse(f"edge {peer or '?'}->{door.role} is not in the manifest", "the edge matrix")
                elif n > MAX_BODY:
                    v = Verdict.refuse(f"body over {MAX_BODY} bytes", status=413)
                else:
                    body = self.rfile.read(n) if n else b""
                    v = door.dispatch(peer, self.command, self.path, body)
                door.audit.record(peer, self.command, self.path, n, v)
                self._answer(v)

            do_GET = do_PUT = do_POST = do_DELETE = _do

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):   # a peer that hangs up, a bad TLS hello: logged, not a traceback
                e = sys.exc_info()[1]
                door.audit.record("?", "-", "-", 0, Verdict.refuse(f"connection error: {type(e).__name__}", status=0))

        self.ctx = context(self.session, self.role, server=True)
        self.server = Server((self.host, self.port), Handler)   # the listener stays plain; each connection wraps itself
        self.port = self.server.server_address[1]
        if background:
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
        else:
            self.server.serve_forever()
        return self.port

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
