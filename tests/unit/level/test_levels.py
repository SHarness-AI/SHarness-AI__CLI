"""The abstraction stack: each compiler deterministic, every vector held, the chain's hashes stable,
the screens drawn in plain at a fixed width."""
import json
import os
from pathlib import Path

import pytest

from sharness_ai.cli import CLI__Main
from sharness_ai.level import Chain, level_of
from sharness_ai.level.l3.L3 import L3
from sharness_ai.level.l4.L4 import L4
from sharness_ai.level.l5.L5 import L5
from sharness_ai.policy import PolicyError, canonical, check, load, policy_hash
from sharness_ai.ui import Term

ROOT = Path(__file__).resolve().parents[3] / "sharness_ai" / "level"


def h(doc):
    import hashlib
    return "sha256:" + hashlib.sha256(canonical(doc)).hexdigest()


def vectors(level):
    return json.loads((ROOT / f"l{level}" / "vectors" / "vectors.json").read_text())


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("SHARNESS_AI_STATE", str(tmp_path / "state.json"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def cli(**kw):
    return CLI__Main(term=Term.plain(width=120), **kw)


class Test_L3:
    def test_sites_compile_to_ports_and_name_the_unheld_host(self):
        doc = vectors(3)["accept"][0]["document"]
        r = L3.compile(doc)
        assert r["document"]["network"] == {"connect_tcp_ports": [443]} and "level" not in r["document"]
        assert r["unheld"] == ["github.com: held as port 443; the host name is not held until sharness.net runs here"]
        assert not check(r["document"])

    @pytest.mark.parametrize("text,expected", [("github.com", ("github.com", 443)), ("http://example.org", ("example.org", 80)),
                                               ("https://pypi.org/simple", ("pypi.org", 443)), ("db.internal:8443", ("db.internal", 8443)),
                                               ("GitHub.com", ("github.com", 443)), ("localhost", ("localhost", 443))])
    def test_site_parsing(self, text, expected):
        assert L3.site(text) == expected

    @pytest.mark.parametrize("text", ["not a host", "ftp://x.org", "x.org:70000", "/etc/passwd", "x"])
    def test_site_refusals(self, text):
        with pytest.raises(PolicyError):
            L3.site(text)

    def test_level_1_row_passes_through_and_is_reported(self):
        doc = next(v for v in vectors(3)["accept"] if v["name"] == "sites-and-a-level-1-row")["document"]
        r = L3.compile(doc)
        assert r["document"]["network"]["connect_tcp_ports"] == [443, 8443] and r["passthrough"]


class Test_L4:
    def test_six_profiles_from_the_example_policies(self):
        assert L4.names() == ["coding-agent", "hello-world", "newsroom-agent", "tool-server", "vault-cli", "web-fetch"]

    def test_blanks_are_substituted_and_a_suffix_survives(self):
        r = L4.compile({"pbp": 1, "level": 4, "profile": "newsroom-agent", "blanks": {"workspace": "/w"}})
        d = r["document"]
        assert d["level"] == 3 and "/w/out" in d["files"]["write"] and "/w" in d["files"]["read"] and "/w/out" in d["files"]["read"]
        assert d["network"] == {"sites": ["send.sgraph.ai"]}

    def test_same_blanks_same_bytes(self):
        a = L4.compile({"pbp": 1, "level": 4, "profile": "coding-agent", "blanks": {"workspace": "/w", "sites": ["b.org", "a.org"]}})
        b = L4.compile({"pbp": 1, "level": 4, "profile": "coding-agent", "blanks": {"sites": ["b.org", "a.org"], "workspace": "/w"}})
        assert canonical(a["document"]) == canonical(b["document"])

    def test_zero_means_no_cap(self):
        d = L4.compile({"pbp": 1, "level": 4, "profile": "tool-server", "blanks": {"workspace": "/w", "memory_mb": 0, "pids": 0}})["document"]
        assert "max_memory_mb" not in d["process"] and "max_pids" not in d["process"]


class Test_L5:
    def test_sentence_and_compile(self):
        doc = {"pbp": 1, "level": 5, "contain": {"agent": "claude", "workspace": "/w", "sites": ["pypi.org", "github.com"], "secrets": []}}
        r = L5.compile(doc)
        assert r["sentence"] == "contain claude to /w, pypi.org, github.com, no secrets"
        assert r["document"] == {"pbp": 1, "level": 4, "profile": "coding-agent", "id": "claude",
                                 "blanks": {"workspace": "/w", "sites": ["github.com", "pypi.org"], "secrets": []}}


class Test_Vectors:
    @pytest.mark.parametrize("level,comp", [(3, L3), (4, L4), (5, L5)])
    def test_every_accept_vector_expands_to_its_hash(self, level, comp):
        v = vectors(level)
        assert v["level"] == level and v["accept"] and v["refuse"]
        for case in v["accept"]:
            r = comp.compile(case["document"])
            assert h(case["document"]) == case["hash"], case["name"]
            assert h(r["document"]) == case["expands_to_hash"], case["name"]
            assert r["document"] == case["expands_to"], case["name"]

    @pytest.mark.parametrize("level,comp", [(3, L3), (4, L4), (5, L5)])
    def test_every_refuse_vector_is_refused(self, level, comp):
        for case in vectors(level)["refuse"]:
            with pytest.raises(PolicyError):
                comp.compile(case["document"])


class Test_Chain:
    DOC = {"pbp": 1, "level": 5, "contain": {"agent": "claude", "workspace": "/w", "sites": ["github.com"]}}

    def test_a_sentence_walks_to_the_kernel_with_one_hash_per_level(self):
        c = Chain.from_document(self.DOC)
        assert [s.level for s in c.steps] == [5, 4, 3, 2, 1]
        assert all(s.hash.startswith("sha256:") for s in c.steps) and len({s.hash for s in c.steps}) == 5
        assert c.v0["network"] == {"connect_tcp_ports": [443]} and not check(c.v0)
        assert c.at(2).hash == policy_hash(c.v0)

    def test_deterministic(self):
        a, b = Chain.from_document(self.DOC), Chain.from_document(self.DOC)
        assert [s.hash for s in a.steps] == [s.hash for s in b.steps]

    def test_a_v0_policy_is_level_2_and_a_bad_level_is_refused(self):
        v0 = Chain.from_document(self.DOC).v0
        assert level_of(v0) == 2 and [s.level for s in Chain.from_document(v0).steps] == [2, 1]
        with pytest.raises(PolicyError):
            level_of({"pbp": 1, "level": 9})

    def test_report_counts_held_and_unheld(self):
        r = Chain.from_document(self.DOC).report()
        assert r["held"] > 10 and len(r["unheld"]) == 1 and "github.com" in r["unheld"][0] and r["hashes"][5]


class Test_CLI_levels:
    def test_contain_dry_run_prints_the_sentence_the_hash_and_the_unheld_row(self, state, capsys):
        assert cli().run(["contain", "--workspace", ".", "--sites", "github.com", "--save", "s.json", "--dry-run", "--", "my-agent"]) == 0
        out = capsys.readouterr().out
        assert "you said        contain my-agent to" in out and "the name        sha256:" in out
        assert "github.com: held as port 443" in out and "saved           s.json" in out
        doc = load("s.json")
        assert doc["level"] == 5 and doc["contain"]["agent"] == "my-agent"

    def test_contain_expect_hash_refuses_a_wrong_name(self, state, capsys):
        assert cli().run(["contain", "--workspace", ".", "--expect-hash", "sha256:0", "--dry-run", "--", "x"]) == 125
        assert "Nothing ran" in capsys.readouterr().out

    def test_explain_draws_one_box_per_level(self, state, capsys):
        assert cli().run(["contain", "--workspace", ".", "--sites", "github.com", "--save", "s.json", "--dry-run", "--", "a"]) == 0
        capsys.readouterr()
        assert cli().run(["explain", "s.json"]) == 0
        out = capsys.readouterr().out
        for s in ("+- 5 intent", "+- 4 profile", "+- 3 rows", "+- 2 manifest", "+- 1 kernel", "what you wrote", "what the kernel is told", "not held"):
            assert s in out, s
        assert cli().run(["--json", "explain", "s.json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert [s["level"] for s in data["steps"]] == [5, 4, 3, 2, 1]

    def test_policy_show_and_check_read_a_levelled_document(self, state, capsys):
        doc = {"pbp": 1, "level": 3, "id": "t", "files": {"read": ["/usr"], "write": [], "exec": ["/usr"]},
               "network": {"sites": ["github.com"]}, "process": {"no_new_privs": True}}
        Path("l3.json").write_text(json.dumps(doc))
        assert cli().run(["policy", "show", "l3.json"]) == 0
        out = capsys.readouterr().out
        assert "level           3: sha256:" in out and "connect_tcp  443" in out and "not held" in out
        assert cli().run(["policy", "check", "l3.json"]) == 0
        assert "well-formed" in capsys.readouterr().out

    def test_profile_list_and_show(self, state, capsys):
        assert cli().run(["profile", "list"]) == 0 and "coding-agent" in capsys.readouterr().out
        assert cli().run(["profile", "show", "hello-world"]) == 0
        out = capsys.readouterr().out
        assert "$workspace" in out and "blanks" in out
        assert cli().run(["profile", "show", "nope"]) == 2

    @pytest.mark.skipif(not (os.name == "posix" and __import__("sharness_ai.landlock", fromlist=["abi"]).abi() >= 1), reason="needs Landlock")
    def test_contain_runs_the_command_under_the_compiled_policy(self, state, capfd):
        code = cli().run(["contain", "--workspace", ".", "--profile", "tool-server", "--", "sh", "-c", "echo from-under; touch /etc/x 2>/dev/null || echo refused"])
        out, err = capfd.readouterr()
        assert code == 0 and "from-under" in out and "refused" in out and "sharness-ai run" in err


class Test_L5_hardening:
    def test_agent_name_is_a_word(self):
        bad = {"pbp": 1, "level": 5, "contain": {"agent": "claude\x1b[31m", "workspace": "/w"}}
        with pytest.raises(PolicyError):
            L5.compile(bad)
        ok = {"pbp": 1, "level": 5, "contain": {"agent": "my-agent.v2", "workspace": "/w"}}
        assert L5.compile(ok)["document"]["id"] == "my-agent.v2"


class Test_Review_2_levels:
    def test_ports_only_at_level_3_is_reported_as_passed_through(self):
        doc = {"pbp": 1, "level": 3, "id": "t", "files": {"read": ["/usr"], "write": [], "exec": ["/usr"]},
               "network": {"connect_tcp_ports": [8443]}, "process": {"no_new_privs": True}}
        r = L3.compile(doc)
        assert r["passthrough"] and r["document"]["network"] == {"connect_tcp_ports": [8443]}

    def test_level_4_sites_order_does_not_change_the_hash(self):
        a = L4.compile({"pbp": 1, "level": 4, "profile": "coding-agent", "blanks": {"workspace": "/w", "sites": ["b.org", "a.org"]}})
        b = L4.compile({"pbp": 1, "level": 4, "profile": "coding-agent", "blanks": {"workspace": "/w", "sites": ["a.org", "b.org"]}})
        assert canonical(a["document"]) == canonical(b["document"])
