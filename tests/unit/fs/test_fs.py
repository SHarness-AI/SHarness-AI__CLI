"""sharness.fs: the vectors held by the twin and by the disk, the disk's containment, and the Boundary
demo: an app under a policy with no write right to the root writes only through the door."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from sharness_ai import landlock
from sharness_ai.cli import CLI__Main
from sharness_ai.door import Client, Session
from sharness_ai.door.Conformance import Conformance
from sharness_ai.fs import FS
from sharness_ai.fs.disk import Disk
from sharness_ai.fs.disk.twin import Twin
from sharness_ai.ui import Term

VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                       "sharness_ai", "fs", "vectors", "vectors.json")


@pytest.fixture
def session(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    return Session.new(str(tmp_path / "s"), ("app", "fs"))


def spec():
    with open(VECTORS) as f:
        return json.load(f)


class Test_FS_normalise:
    @pytest.mark.parametrize("raw", ["../../etc/passwd", "/etc/passwd", "a/../../b", "", "a\x00b", ".."])
    def test_outside_the_root_is_none(self, raw):
        assert FS.normalise(raw) is None

    @pytest.mark.parametrize("raw,rel", [("src/main.py", "src/main.py"), ("./a/./b", "a/b"), ("a//b", "a/b")])
    def test_inside_is_normalised(self, raw, rel):
        assert FS.normalise(raw) == rel


class Test_Vectors:
    @pytest.mark.parametrize("target", ["disk.twin", "disk"])
    def test_every_vector_holds(self, session, tmp_path, target):
        s = spec()
        store = Twin() if target == "disk.twin" else Disk(str(tmp_path / "root"))
        door = FS(session, store, policy=s["door_policy_for_these_vectors"])
        port = door.serve(background=True)
        try:
            results = Conformance(Client(session, "app", "fs", port)).run(s["vectors"])
        finally:
            door.stop()
        summary = Conformance.summary(results)
        assert summary["failed"] == [], summary
        assert summary["of"] == len(s["vectors"]) >= 18


class Test_Disk:
    def test_symlink_escape_is_refused_and_writes_are_never_executable(self, session, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        os.symlink(outside, root / "link")
        door = FS(session, Disk(str(root)))
        port = door.serve(background=True)
        try:
            c = Client(session, "app", "fs", port)
            status, data = c.request("PUT", "/v0/files/link/x.txt", b"x")
            assert status == 403 and "symlink" in data["reason"] and not (outside / "x.txt").exists()
            status, _ = c.request("PUT", "/v0/files/bin/tool.sh", b"#!/bin/sh\necho hi\n")
            assert status == 201 and not os.access(root / "bin" / "tool.sh", os.X_OK)
            status, _ = c.request("POST", "/v0/files/log.txt/append", b"a\n")
            status, _ = c.request("POST", "/v0/files/log.txt/append", b"b\n")
            assert (root / "log.txt").read_text() == "a\nb\n"
        finally:
            door.stop()


class Test_Boundary_demo:
    @pytest.mark.skipif(landlock.abi() < 1, reason="needs Landlock")
    def test_the_app_cannot_write_the_root_directly_but_can_through_the_door(self, session, tmp_path):
        """The kernel half and the door half together: the app's policy has no write right to the
        root; its direct write is EACCES; its write through sharness.fs lands, under the rows."""
        root = tmp_path / "root"
        door = FS(session, Disk(str(root)))
        port = door.serve(background=True)
        try:
            repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            policy = {"pbp": 1, "id": "app", "files": {"read": sorted({"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", repo,
                                                                       os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix),
                                                                       str(tmp_path)}),
                                                       "write": [], "exec": ["/usr", "/lib", "/lib64", "/bin", "/sbin", os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix)]},
                      "network": {"connect_tcp_ports": [port]}, "process": {"no_new_privs": True}}
            pp = tmp_path / "app.json"
            pp.write_text(json.dumps(policy))
            code = f"""
import os, sys
sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))!r})
from sharness_ai.door import Client, Session
try:
    open({str(root / 'direct.txt')!r}, 'w').close(); print('direct: WROTE')
except PermissionError as e:
    print('direct: refused by the kernel', e.errno)
s = Session.load({str(tmp_path / 's')!r})
status, data = Client(s, 'app', 'fs', {port}).request('PUT', '/v0/files/via-door.txt', b'hello')
print('door:', status)
status, data = Client(s, 'app', 'fs', {port}).request('PUT', '/v0/files/key.txt', b'-----BEGIN ' + b'PRIVATE KEY-----')
print('door key:', status, data.get('reason'))
"""
            env = dict(os.environ, PYTHONPATH=repo)              # the package, uninstalled (as in CI); -P keeps the cwd out
            r = subprocess.run([sys.executable, "-P", "-s", "-m", "sharness_ai", "run", "--policy", str(pp), "--quiet", "--",
                                sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60, env=env)
            out = r.stdout
            assert "direct: refused by the kernel 13" in out, (out, r.stderr)
            assert "door: 201" in out and "door key: 403" in out, (out, r.stderr)
            assert (root / "via-door.txt").read_text() == "hello" and not (root / "direct.txt").exists()
        finally:
            door.stop()


class Test_CLI_fs:
    def test_session_serve_once_and_conformance(self, tmp_path, monkeypatch, capsys):
        if not shutil.which("openssl"):
            pytest.skip("needs openssl")
        monkeypatch.setenv("SHARNESS_AI_STATE", str(tmp_path / "state.json"))
        cli = lambda: CLI__Main(term=Term.plain(width=120))  # noqa: E731
        assert cli().run(["session", "new", "--dir", str(tmp_path / "s"), "--roles", "app", "fs"]) == 0
        assert "app->fs" in capsys.readouterr().out
        assert cli().run(["fs", "serve", "--target", "disk.twin", "--session", str(tmp_path / "s"), "--port", "0", "--once"]) == 0
        assert "sharness.fs.disk.twin is listening" in capsys.readouterr().out
        assert cli().run(["door", "conformance", "sharness.fs.disk.twin"]) == 0
        out = capsys.readouterr().out
        assert "18/18 held" in out and "caveat" in out
        assert cli().run(["--json", "door", "conformance", "sharness.fs.disk"]) == 0
        assert json.loads(capsys.readouterr().out)["failed"] == []


class Test_Hardening:
    """The review of 26 Oct 2026: traversal by encoding or query, a directory swapped for a link, the twin's cap,
    a reason that could carry a newline, a Content-Length that is not a number."""

    def test_encoded_traversal_and_query_strings_are_refused(self):
        assert FS.normalise("%2e%2e/etc/passwd") is None
        assert FS.normalise("..%2f..%2fetc") is None
        assert FS.normalise("notes.txt?x=../../etc") == "notes.txt"
        assert FS.normalise("a%20b.txt") == "a b.txt"
        assert FS.normalise("x" * 1025) is None

    def test_a_directory_that_is_a_symlink_is_refused_at_open_time(self, session, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir(), outside.mkdir()
        os.symlink(outside, root / "docs")                       # a link where a directory should be
        door = FS(session, Disk(str(root)))
        port = door.serve(background=True)
        try:
            c = Client(session, "app", "fs", port)
            for method, path in (("PUT", "/v0/files/docs/x.txt"), ("POST", "/v0/files/docs/x.txt/append"), ("POST", "/v0/mkdir")):
                body = b'{"path": "docs/sub"}' if path == "/v0/mkdir" else b"x"
                status, data = c.request(method, path, body)
                assert status == 403 and "symbolic link" in data["reason"], (method, path, data)
            assert not list(outside.iterdir())
            status, _ = c.request("PUT", "/v0/files/ok/x.txt", b"x")
            assert status == 201 and (root / "ok" / "x.txt").read_text() == "x"
        finally:
            door.stop()

    def test_twin_has_a_cap(self):
        t = Twin(max_total=10)
        t.write("a", b"12345")
        with pytest.raises(OSError):
            t.write("b", b"123456")
        t.write("a", b"1234567890")                               # replacing within the cap is fine
        with pytest.raises(OSError):
            t.append("a", b"x")

    def test_a_reason_is_one_clean_line(self):
        from sharness_ai.door.Verdict import Verdict
        v = Verdict.refuse("bad\npath\x1b[31m" + "x" * 500)
        assert "\n" not in v.reason and "\x1b" not in v.reason and len(v.reason) <= 300

    def test_bad_content_length_is_400(self, session):
        import http.client
        from sharness_ai.door.Client import context
        door = FS(session, Twin())
        port = door.serve(background=True)
        try:
            conn = http.client.HTTPSConnection("localhost", port, context=context(session, "app", server=False), timeout=10)
            conn.putrequest("PUT", "/v0/files/x", skip_accept_encoding=True)
            conn.putheader("Content-Length", "not-a-number")
            conn.endheaders()
            r = conn.getresponse()
            assert r.status == 400
        finally:
            door.stop()


class Test_Review_2_fs:
    def test_two_writers_to_one_name_both_land(self, session, tmp_path):
        import threading
        door = FS(session, Disk(str(tmp_path / "root")))
        port = door.serve(background=True)
        failures = []

        def worker(tag):
            c = Client(session, "app", "fs", port)
            for i in range(40):
                status, data = c.request("PUT", "/v0/files/same.txt", f"{tag}{i}".encode())
                if status != 201:
                    failures.append((tag, i, status, data))
        try:
            ts = [threading.Thread(target=worker, args=(t,)) for t in ("a", "b")]
            [t.start() for t in ts]
            [t.join() for t in ts]
        finally:
            door.stop()
        assert failures == []
        assert (tmp_path / "root" / "same.txt").read_text()[0] in "ab"
        assert not [p for p in (tmp_path / "root").iterdir() if p.name.startswith(".sharness-fs-")]

    def test_a_long_file_name_is_fine(self, session, tmp_path):
        door = FS(session, Disk(str(tmp_path / "root")))
        port = door.serve(background=True)
        try:
            status, _ = Client(session, "app", "fs", port).request("PUT", "/v0/files/" + "n" * 240, b"x")
            assert status == 201
        finally:
            door.stop()
