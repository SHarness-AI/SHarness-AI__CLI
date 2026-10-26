"""doctor (the chain of checks) and help (the surface read from the parser), plus the pinned list
of top-level commands: adding one is a deliberate edit here, as sgit's CLI does it."""
import json
import sys

import pytest

from sharness_ai import landlock
from sharness_ai.cli import CLI__Main
from sharness_ai.cli.doctor.Check__Result import FAIL, PASS, SKIP, WARN, Check__Result
from sharness_ai.ui import Prompt, Term

TOP_LEVEL = {"guide", "doctor", "help", "probe", "policy", "run", "hello", "components", "contain", "profile", "explain",
             "bash", "net", "kms", "fs", "llm", "launcher"}


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("SHARNESS_AI_STATE", str(tmp_path / "state.json"))
    monkeypatch.chdir(tmp_path)


def cli(**kw):
    return CLI__Main(term=Term.plain(width=110), **kw)


class Test_Doctor:
    def test_seven_checks_in_order_and_a_verdict(self, state, capsys):
        code = cli().run(["doctor"])
        out = capsys.readouterr().out
        for n in ("[1/7]", "kernel", "landlock_files", "landlock_tcp", "network_namespace", "cgroups", "max_pids",
                  "write_probe", "[7/7]", "overall"):
            assert n in out, n
        assert code in (0, 1)
        if landlock.abi() >= 1:
            assert code == 0 and ("healthy" in out or "degraded" in out)

    def test_json_report(self, state, capsys):
        cli().run(["--json", "doctor"])
        r = json.loads(capsys.readouterr().out)
        assert r["schema"] == "sharness-ai.doctor/v0" and len(r["checks"]) == 7
        assert r["overall"] in (PASS, WARN, FAIL)
        assert all(c["status"] in (PASS, WARN, FAIL, SKIP) for c in r["checks"])

    def test_no_kernel_fails_the_first_check_and_skips_the_rest(self, state, monkeypatch, capsys):
        monkeypatch.setattr(sys, "platform", "emscripten")
        assert cli().run(["doctor"]) == 1
        out = capsys.readouterr().out
        assert "no kernel" in out and "skipped: an earlier check failed" in out and "FAILED" in out
        assert "playground" in out                          # the hint says where a kernel is

    @pytest.mark.skipif(landlock.abi() < 1, reason="needs a kernel with Landlock")
    def test_write_probe_is_refused_by_the_kernel(self, state, capsys):
        cli().run(["--json", "doctor"])
        r = json.loads(capsys.readouterr().out)
        probe = [c for c in r["checks"] if c["name"] == "write_probe"][0]
        assert probe["status"] == PASS and "EACCES" in probe["message"]

    def test_result_dataclass(self):
        r = Check__Result("x", PASS, "ok").done(0.0)
        assert r.as_dict()["status"] == PASS and r.duration_ms > 0


class Test_Help_Reference:
    def test_json_names_every_top_level_command_with_help(self, state, capsys):
        assert cli().run(["help", "--format", "json"]) == 0
        ref = json.loads(capsys.readouterr().out)
        names = {c["path"].split()[-1] for c in ref["tree"]["commands"]}
        assert names == TOP_LEVEL, names ^ TOP_LEVEL
        assert all(c["help"] for c in ref["tree"]["commands"])
        policy = [c for c in ref["tree"]["commands"] if c["path"] == "sharness-ai policy"][0]
        assert {c["path"].split()[-1] for c in policy["commands"]} == {"hash", "check", "show", "translate", "new", "edit"}
        run = [c for c in ref["tree"]["commands"] if c["path"] == "sharness-ai run"][0]
        assert any(o["flags"] == ["--expect-hash"] for o in run["options"])

    def test_text_lists_the_tree(self, state, capsys):
        assert cli().run(["help"]) == 0
        out = capsys.readouterr().out
        assert "sharness-ai policy new" in out and "sharness-ai run" in out and "--format json" in out

    def test_top_level_is_pinned(self):
        """Adding a top-level command is a deliberate edit of TOP_LEVEL above (sgit's rule 9)."""
        parser = CLI__Main().build_parser()
        sub = [a for a in parser._actions if hasattr(a, "choices") and a.choices and "probe" in a.choices][0]
        assert set(sub.choices) == TOP_LEVEL


class Test_Prompt_Timeout:
    def test_a_silent_terminal_gets_the_default(self, monkeypatch, capsys):
        import select as sel
        monkeypatch.setattr(sel, "select", lambda r, w, x, t: ([], [], []))
        p = Prompt(Term.plain(interactive=True), timeout=0.01)
        assert p.ask("ports?", default="none") == "none"
        assert "no answer" in capsys.readouterr().out
