"""The door kit: a session by openssl, a door that reads the caller's role and refuses the wrong edge,
a client that refuses the wrong callee, the contract, the rows."""
import shutil

import pytest

from sharness_ai.door import EDGES, Client, Contract, Door, Rows, Session, Verdict
from sharness_ai.door.Client import DoorError
from sharness_ai.door.Session import SessionError
from sharness_ai.fs import FS
from sharness_ai.fs.disk.twin import Twin

needs_openssl = pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl to issue a session")


@pytest.fixture
def session(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    return Session.new(str(tmp_path / "s"), ("app", "fs", "net"))


class Test_Session:
    @needs_openssl
    def test_new_issues_one_identity_per_role_and_destroys_the_ca_key(self, tmp_path):
        s = Session.new(str(tmp_path / "s"), ("app", "fs"))
        assert (tmp_path / "s" / "ca.crt").exists() and not (tmp_path / "s" / "ca.key").exists()
        for r in ("app", "fs"):
            assert (tmp_path / "s" / f"{r}.crt").exists() and (tmp_path / "s" / f"{r}.key").exists()
            assert s.spiffe(r) == f"spiffe://{s.id}/{r}"
        again = Session.load(str(tmp_path / "s"))
        assert again.id == s.id and again.roles == ("app", "fs")

    def test_unknown_role_is_refused_before_openssl_runs(self, tmp_path):
        with pytest.raises(SessionError):
            Session.new(str(tmp_path / "s"), ("app", "root"))

    def test_edges_are_the_matrix(self):
        assert ("app", "fs") in EDGES and ("net", "fs") not in EDGES and ("app", "kms") not in EDGES


class Test_Door:
    def test_caller_role_is_read_and_the_edge_checked_both_ways(self, session):
        door = FS(session, Twin())
        port = door.serve(background=True)
        try:
            status, data = Client(session, "app", "fs", port).request("GET", "/v0/hello")
            assert status == 200 and data["door"] == "sharness.fs" and data["targets"] == {"sharness.fs.disk.twin": "twin"}
            status, data = Client(session, "net", "fs", port).request("GET", "/v0/hello")
            assert status == 403 and "edge net->fs" in data["reason"]
            with pytest.raises(DoorError):                       # the caller checks the callee's role too
                Client(session, "app", "net", port).request("GET", "/v0/hello")
        finally:
            door.stop()

    def test_a_request_outside_the_contract_is_404_and_logged(self, session):
        door = FS(session, Twin())
        port = door.serve(background=True)
        try:
            c = Client(session, "app", "fs", port)
            status, data = c.request("POST", "/v0/nope", b"x")
            assert status == 404 and "not in what this door accepts" in data["reason"]
            status, log = c.request("GET", "/v0/log")
            assert status == 200 and any(x["path"] == "/v0/nope" and not x["allowed"] for x in log["lines"])
            assert all("body" not in x for x in log["lines"])
        finally:
            door.stop()

    def test_policy_answers_with_its_hash_and_contract(self, session):
        door = FS(session, Twin())
        port = door.serve(background=True)
        try:
            status, data = Client(session, "app", "fs", port).request("GET", "/v0/policy")
            assert status == 200 and data["hash"].startswith("sha256:") and "PUT /v0/files/{path}" in data["contract"]["routes"]
        finally:
            door.stop()


class Test_Contract_and_Rows:
    def test_contract_routes_and_hashes(self):
        import sharness_ai.fs as fs
        import os
        c = Contract(os.path.dirname(fs.__file__))
        route, params = c.match("PUT", "/v0/files/src/main.py")
        assert route["op"] == "write" and params == {"path": "src/main.py"}
        assert c.match("PATCH", "/v0/files/x") == (None, None)
        assert c.accepts_hash.startswith("sha256:") and c.emits_hash != c.accepts_hash

    def test_rows_predicates(self):
        rows = Rows([{"resource": "/ledger.txt", "op": "*", "where": {"append_only": True}},
                     {"resource": "/notes", "op": "*", "where": {"max_bytes": 10}}])
        assert rows.verdict("append", "/ledger.txt", b"x").allowed
        v = rows.verdict("write", "/ledger.txt", b"x")
        assert not v.allowed and v.row == "append_only /ledger.txt"
        assert not rows.verdict("delete", "/ledger.txt").allowed
        assert not rows.verdict("write", "/notes/a.txt", b"x" * 11).allowed and rows.verdict("write", "/notes/a.txt", b"x" * 10).allowed
        v = rows.verdict("write", "/any.txt", b"-----BEGIN " + b"PRIVATE KEY-----")      # split: the tree holds no key shape in clear
        assert not v.allowed and "a private key" in v.reason
        assert not rows.verdict("write", "/k", b"sgit_private_vault_abc").allowed
        assert rows.verdict("write", "/ok.txt", b"plain text").allowed

    def test_unknown_predicate_is_refused_at_load(self):
        with pytest.raises(ValueError):
            Rows([{"resource": "/x", "where": {"content_schema": "x.json"}}])

    def test_verdict_payload(self):
        assert Verdict.refuse("why", "row").payload() == {"allowed": False, "status": 403, "reason": "why", "row": "row"}
        assert Door.role == "door"


class Test_Session_hardening:
    @needs_openssl
    def test_keys_are_private_and_the_ca_key_is_gone_even_when_a_role_fails(self, tmp_path, monkeypatch):
        import stat
        s = Session.new(str(tmp_path / "s"), ("app", "fs"))
        for name in ("app.key", "fs.key"):
            assert stat.S_IMODE((tmp_path / "s" / name).stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "s").stat().st_mode) == 0o700 and not (tmp_path / "s" / "ca.key").exists()
        # a failure half-way: the CA key must still be gone
        import sys
        S = sys.modules["sharness_ai.door.Session"]          # the package re-exports the class under the module's name
        calls = {"n": 0}
        real = S._run

        def flaky(args, cwd):
            calls["n"] += 1
            if calls["n"] == 3:
                raise SessionError("simulated openssl failure")
            return real(args, cwd)
        monkeypatch.setattr(S, "_run", flaky)
        with pytest.raises(SessionError):
            Session.new(str(tmp_path / "t"), ("app", "fs"))
        assert not (tmp_path / "t" / "ca.key").exists()
        with pytest.raises(SessionError):
            Session.new(str(tmp_path / "u"), ("app",), days=0)
