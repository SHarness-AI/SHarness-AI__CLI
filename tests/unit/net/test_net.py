"""sharness.net.proxy: the rows, the SNI parse, and the proxy against a local HTTP server standing in
for the internet: allowed, off the list, an IP literal, a method the proxy does not take, the log."""
import http.client
import shutil
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sharness_ai.door import Client, Session
from sharness_ai.door.Verdict import Audit
from sharness_ai.net import NET, NetRows
from sharness_ai.net.proxy.Proxy import Proxy, peer_uid, sni


class Test_NetRows:
    def test_exact_suffix_ports_and_literals(self):
        r = NetRows(["github.com", "*.pypi.org"], ports=(443,))
        assert r.allow("github.com", 443).allowed and r.allow("GitHub.com.", 443).allowed
        assert r.allow("files.pythonhosted.org", 443).allowed is False
        assert r.allow("files.pypi.org", 443).allowed and r.allow("pypi.org", 443).allowed
        assert "allowlist" in r.allow("example.com", 443).reason
        assert "IP literals" in r.allow("1.1.1.1", 443).reason and "IP literals" in r.allow("[::1]", 443).reason
        assert "port 80" in r.allow("github.com", 80).reason
        assert "not a host" in r.allow("bad host", 443).reason and "no host" in r.allow("", 443).reason


class Test_SNI:
    def test_parses_a_client_hello_and_ignores_other_bytes(self):
        import ssl
        import socket
        # a real ClientHello, captured from the ssl module into a socket pair
        a, b = socket.socketpair()
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        a.setblocking(False)
        wrapped = ctx.wrap_socket(a, server_hostname="github.com", do_handshake_on_connect=False)
        try:
            wrapped.do_handshake()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, OSError):
            pass
        hello = b.recv(65536)
        assert sni(hello) == "github.com"
        assert sni(b"GET / HTTP/1.1\r\n") is None and sni(b"") is None


@pytest.fixture
def world(tmp_path):
    """A local HTTP server standing in for a site, and the host name it answers to: localhost."""
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"hello from the world"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


class Test_Proxy:
    def _proxy(self, hosts, ports, uid=None):
        audit = Audit("sharness.net.proxy")
        p = Proxy(NetRows(hosts, ports=ports), audit, allowed_uid=uid)
        return p, p.serve(background=True), audit

    def test_forward_allowed_and_refusals(self, world):
        p, port, audit = self._proxy(["localhost"], (world,))
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", f"http://localhost:{world}/x")
            r = c.getresponse()
            assert r.status == 200 and r.read() == b"hello from the world"
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", f"http://example.com:{world}/x")
            r = c.getresponse()
            assert r.status == 403 and b"not on the allowlist" in r.read()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", f"http://127.0.0.1:{world}/x")
            r = c.getresponse()
            assert r.status == 403 and b"IP literals" in r.read()
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/not-a-proxy-request")
            assert c.getresponse().status == 400
            lines = audit.dump()
            assert [x["allowed"] for x in lines] == [True, False, False, False]
            assert all("body" not in x for x in lines)
        finally:
            p.stop()

    def test_connect_tunnel_relays_bytes(self, world):
        p, port, audit = self._proxy(["localhost"], (world,))
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.set_tunnel("localhost", world)
            c.request("GET", "/through-the-tunnel")
            r = c.getresponse()
            assert r.status == 200 and r.read() == b"hello from the world"
            c.close()
            import time
            time.sleep(0.2)
            assert any(x["method"] == "CONNECT" and x["allowed"] for x in audit.dump())
        finally:
            p.stop()

    def test_connect_to_a_host_off_the_list_is_403(self, world):
        p, port, audit = self._proxy(["localhost"], (world,))
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.set_tunnel("example.com", world)
            with pytest.raises(OSError):
                c.request("GET", "/")
        finally:
            p.stop()
        assert any(x["method"] == "CONNECT" and not x["allowed"] for x in audit.dump())

    def test_another_uid_is_refused(self, world):
        import os
        p, port, audit = self._proxy(["localhost"], (world,), uid=os.geteuid() + 12345)
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", f"http://localhost:{world}/x")
            r = c.getresponse()
            assert r.status == 403 and b"uid" in r.read()
        finally:
            p.stop()

    def test_peer_uid_reads_the_socket_table(self, world):
        import os
        import socket
        s = socket.create_connection(("127.0.0.1", world))
        try:
            assert peer_uid(s.getsockname()) == os.geteuid()
        finally:
            s.close()


class Test_NET_door:
    def test_hello_names_the_proxy_and_the_rows(self, tmp_path):
        if not shutil.which("openssl"):
            pytest.skip("needs openssl")
        s = Session.new(str(tmp_path / "s"), ("app", "net", "launcher"))
        door = NET(s, policy={"pbp": 1, "id": "sharness.net", "hosts": ["github.com"], "ports": [443]})
        door_port, proxy_port = door.start()
        try:
            status, data = Client(s, "app", "net", door_port).request("GET", "/v0/hello")
            assert status == 200 and data["proxy_port"] == proxy_port and data["rows"]["hosts"] == ["github.com"]
            assert data["targets"] == {"sharness.net.proxy": "live"}
            status, _ = Client(s, "app", "net", door_port).request("GET", "/v0/log")
            assert status == 403
        finally:
            door.stop()
