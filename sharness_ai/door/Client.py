"""A caller of a door: mutual TLS with the caller's certificate, the callee's role checked from its
certificate before the first byte of the request (the caller checks the callee, so a compromised
process cannot pose as sharness.fs to the app)."""
import http.client
import json
import ssl

from sharness_ai.door.Session import Session


class DoorError(RuntimeError):
    pass


def peer_role(sock) -> str:
    for kind, val in sock.getpeercert().get("subjectAltName", ()):
        if kind == "URI" and val.startswith("spiffe://"):
            return val.rsplit("/", 1)[-1]
    return ""


def context(session: Session, role: str, server: bool) -> ssl.SSLContext:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(session.cert(role), session.key(role))
    c.load_verify_locations(session.ca)
    c.verify_mode = ssl.CERT_REQUIRED
    return c


class Client:
    def __init__(self, session: Session, role: str, callee: str, port: int, host: str = "localhost"):
        self.session, self.role, self.callee, self.port, self.host = session, role, callee, port, host
        self.ctx = context(session, role, server=False)

    def request(self, method: str, path: str, body: bytes = None, headers: dict = None):
        """(status, json or text). Raises DoorError if the server is not the role expected."""
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=10)
        try:
            conn.connect()
            who = peer_role(conn.sock)
            if who != self.callee:
                raise DoorError(f"the process on port {self.port} is {who or 'unknown'}, not sharness.{self.callee}: refused before any request")
            h = {"Content-Length": str(len(body or b""))}
            h.update(headers or {})
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else {}
            except ValueError:
                return r.status, raw.decode("utf-8", "replace")
        except (OSError, ssl.SSLError) as e:
            raise DoorError(f"could not reach sharness.{self.callee} on port {self.port}: {e}") from None
        finally:
            conn.close()
