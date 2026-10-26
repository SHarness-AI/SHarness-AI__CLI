"""sharness.net.proxy: an HTTP proxy on loopback for one uid.

`CONNECT host:port` opens a tunnel to the host when the rows allow it and relays bytes both ways;
the first bytes of the tunnel are read for the TLS client hello's SNI, which must name the same
host (a tunnel to one name carrying another is domain fronting and is cut). A plain request with
an absolute URL (`GET http://host/path`) is forwarded once, Connection: close. Every request is one
audit line: method, host:port, bytes, verdict, the row. The connecting process's uid is read from
/proc/net/tcp (the socket table names the owner of every loopback socket), so a proxy started for
one uid answers no other. Kept small on purpose: it does not terminate TLS, cache, or speak HTTP/2."""
import select
import socket
import socketserver
import struct
import threading

from sharness_ai.door.Verdict import Audit, Verdict
from sharness_ai.net.Rows import NetRows

TIMEOUT = 30
IDLE = 300
MAX_HEAD = 16 << 10


def peer_uid(addr: tuple):
    """The uid that owns the loopback socket bound to `addr` (ip, port), from /proc/net/tcp; None if unknown."""
    ip, port = addr[0], addr[1]
    want = struct.unpack("<I", socket.inet_aton(ip))[0]
    try:
        with open("/proc/net/tcp") as f:
            next(f)
            for line in f:
                cols = line.split()
                local_ip, local_port = cols[1].split(":")
                if int(local_port, 16) == port and int(local_ip, 16) == want:
                    return int(cols[7])
    except (OSError, ValueError, IndexError):
        pass
    return None


def sni(hello: bytes):
    """The server name in a TLS ClientHello, or None (not TLS, or no SNI)."""
    try:
        if hello[0] != 0x16 or hello[5] != 0x01:
            return None
        p = 43 + hello[43] + 1                              # session id
        p += 2 + struct.unpack("!H", hello[p:p + 2])[0]     # cipher suites
        p += 1 + hello[p]                                   # compression
        end = p + 2 + struct.unpack("!H", hello[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", hello[p:p + 4])
            p += 4
            if etype == 0:
                nlen = struct.unpack("!H", hello[p + 3:p + 5])[0]
                return hello[p + 5:p + 5 + nlen].decode("ascii", "replace").lower()
            p += elen
    except (IndexError, struct.error):
        return None
    return None


class Proxy:
    def __init__(self, rows: NetRows, audit: Audit, port: int = 0, host: str = "127.0.0.1", allowed_uid: int = None):
        self.rows, self.audit, self.host, self.port, self.allowed_uid = rows, audit, host, port, allowed_uid
        self.server = None
        self.active = 0
        self.lock = threading.Lock()

    def decide(self, peer_addr, method: str, host: str, port: int) -> Verdict:
        if self.allowed_uid is not None:
            uid = peer_uid(peer_addr)
            if uid != self.allowed_uid:
                return Verdict.refuse(f"the caller is uid {uid}, not the shell's uid {self.allowed_uid}", "one uid per proxy")
        with self.lock:
            if self.active >= self.rows.max_connections:
                return Verdict.refuse(f"{self.active} connections open: the row's max_connections", f"max_connections {self.rows.max_connections}")
        return self.rows.allow(host, port)

    def serve(self, background: bool = True) -> int:
        proxy = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = TIMEOUT

            def _reply(self, status: int, text: str, reason: str = ""):
                body = (reason + "\n").encode()
                self.wfile.write(f"HTTP/1.1 {status} {text}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\nX-Sharness-Door: sharness.net.proxy\r\n\r\n".encode() + body)

            def handle(self):
                head = b""
                while b"\r\n\r\n" not in head and len(head) < MAX_HEAD:
                    chunk = self.rfile.readline(MAX_HEAD)
                    if not chunk:
                        return
                    head += chunk
                    if head.endswith(b"\r\n\r\n") or chunk in (b"\r\n", b"\n"):
                        break
                line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                parts = line.split()
                if len(parts) != 3:
                    self._reply(400, "Bad Request", "one request line, please")
                    return
                method, target, _version = parts
                if method == "CONNECT":
                    host, _, port = target.rpartition(":")
                    port = int(port) if port.isdigit() else 443
                    self._tunnel(host, port)
                elif target.lower().startswith("http://"):
                    rest = target[7:]
                    hostport, _, path = rest.partition("/")
                    host, _, port = hostport.rpartition(":") if ":" in hostport else (hostport, "", "")
                    self._forward(method, host or hostport, int(port) if port.isdigit() else 80, "/" + path, head)
                else:
                    v = Verdict.refuse("this is a proxy: send CONNECT host:443 or an absolute http:// URL", "ACCEPTS.json", status=400)
                    proxy.audit.record(f"uid {peer_uid(self.client_address)}", method, target, 0, v)
                    self._reply(400, "Bad Request", v.reason)

            def _open(self, method, host, port):
                v = proxy.decide(self.client_address, method, host, port)
                if not v.allowed:
                    proxy.audit.record(f"uid {peer_uid(self.client_address)}", method, f"{host}:{port}", 0, v)
                    self._reply(403, "Forbidden", f"refused by sharness.net.proxy: {v.reason} (row: {v.row})")
                    return None
                try:
                    up = socket.create_connection((host, port), timeout=TIMEOUT)
                except OSError as e:
                    v = Verdict.refuse(f"the host did not answer: {e}", status=502)
                    proxy.audit.record(f"uid {peer_uid(self.client_address)}", method, f"{host}:{port}", 0, v)
                    self._reply(502, "Bad Gateway", v.reason)
                    return None
                # the decision is audited when it is made, in order; the byte count is filled in when the relay ends
                self.line = proxy.audit.record(f"uid {peer_uid(self.client_address)}", method, f"{host}:{port}", 0, v)
                return up

            def _tunnel(self, host, port):
                up = self._open("CONNECT", host, port)
                if up is None:
                    return
                self.wfile.write(b"HTTP/1.1 200 Connection established\r\nX-Sharness-Door: sharness.net.proxy\r\n\r\n")
                self.wfile.flush()
                first = self.connection.recv(16384)
                name = sni(first)
                if name and name != host.lower():
                    up.close()
                    v = Verdict.refuse(f"the TLS hello names {name}, the tunnel was for {host}", "no domain fronting")
                    self.line.update({"allowed": False, "status": 403, "reason": v.reason, "row": v.row, "bytes": len(first)})
                    return
                self.line["bytes"] = self._relay(up, first)
                self.line["sni"] = name or ""

            def _forward(self, method, host, port, path, head):
                up = self._open(method, host, port)
                if up is None:
                    return
                lines = head.decode("latin-1", "replace").split("\r\n")
                lines[0] = f"{method} {path} HTTP/1.1"
                lines = [x for x in lines if x and not x.lower().startswith(("proxy-connection:", "connection:"))] + ["Connection: close", "", ""]
                self.line["path"] = f"{host}:{port}{path}"
                self.line["bytes"] = self._relay(up, "\r\n".join(lines).encode("latin-1", "replace"))

            def _relay(self, up, first: bytes) -> int:
                total = len(first)
                with proxy.lock:
                    proxy.active += 1
                try:
                    if first:
                        up.sendall(first)
                    down = self.connection
                    while True:
                        r, _, _ = select.select([up, down], [], [], IDLE)
                        if not r:
                            break
                        done = False
                        for s in r:
                            data = s.recv(65536)
                            if not data:
                                done = True
                                break
                            total += len(data)
                            (down if s is up else up).sendall(data)
                        if done:
                            break
                finally:
                    with proxy.lock:
                        proxy.active -= 1
                    up.close()
                return total

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request, client_address):
                proxy.audit.record("?", "-", "-", 0, Verdict.refuse("connection error", status=0))

        self.server = Server((self.host, self.port), Handler)
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
