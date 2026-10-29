"""The screens of the front door, drawn in plain at a fixed width so the assertions read like them.
Design: sharness.ai/articles/the-cli-is-the-front-door.html"""
import json
import os
import sys

import pytest

from sharness_ai import landlock
from sharness_ai.cli import CLI__Main, main
from sharness_ai.cli.CLI__Components import EXIT_NOT_BUILT
from sharness_ai.policy import load, policy_hash
from sharness_ai.ui import Term

ROOT    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
P2      = os.path.join(ROOT, "experiments", "policies", "p2-tool-server.json")
needs_landlock = pytest.mark.skipif(landlock.abi() < 1, reason="needs a kernel with Landlock")


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("SHARNESS_AI_STATE", str(tmp_path / "state.json"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def cli(answers=None, width=110, interactive=False):
    return CLI__Main(term=Term.plain(width=width, interactive=interactive), answers=answers)


class Test_Guide:
    def test_no_arguments_on_a_pipe_is_the_usage_text(self, state, capsys):
        assert main([]) == 0
        assert "usage: sharness-ai" in capsys.readouterr().out

    def test_no_arguments_on_a_terminal_is_the_guide(self, state, capsys):
        assert cli(answers=["q"], interactive=True).run([]) == 0
        out = capsys.readouterr().out
        for s in ("sharness-ai v", "where you are", "the ladder", "1  probe", "4  run", "what next?", "6 components"):
            assert s in out, s

    def test_guide_once_has_no_menu_and_ends_with_the_next_step(self, state, capsys):
        assert cli().run(["guide", "--once"]) == 0
        out = capsys.readouterr().out
        assert "what next?" not in out and "next" in out and "[ok] 1  probe" in out

    def test_menu_runs_a_command_then_redraws(self, state, capsys):
        assert cli(answers=["6", "q"], interactive=True).run([]) == 0
        out = capsys.readouterr().out
        assert "the operating system a process sees" in out and out.count("what next?") == 2

    def test_ladder_ticks_what_was_done_and_draws_the_policy_here(self, state, capsys):
        assert cli().run(["policy", "new", "t.json", "-y", "--write", "/work/out"]) == 0
        capsys.readouterr()
        assert cli().run(["guide", "--once"]) == 0
        out = capsys.readouterr().out
        assert "[ok] 3  policy     t  sha256:" in out and "the policy      t   t.json" in out and "write /work/out" in out


class Test_Policy_screens:
    def test_new_with_flags_writes_a_well_formed_policy_and_prints_its_hash(self, state, capsys):
        assert cli().run(["policy", "new", "t.json", "-y", "--write", "/work/out", "--ports", "443, 8443", "--memory", "0"]) == 0
        out = capsys.readouterr().out
        p = load("t.json")
        h = policy_hash(p)
        assert p["files"]["write"] == ["/work/out"] and p["network"] == {"connect_tcp_ports": [443, 8443]}
        assert "max_memory_mb" not in p["process"] and p["process"]["max_pids"] == 16
        assert f"written         t.json   {h}" in out and f"--expect-hash {h}" in out
        assert "connect_tcp  443 8443" in out and "memory  no cap" in out

    def test_new_asks_five_questions_and_shows_each_default(self, state, capsys):
        answers = ["", "/work/out", "", "443", "64"]
        assert cli(answers=answers).run(["policy", "new", "t.json"]) == 0
        out = capsys.readouterr().out
        for s in ("1/5  what may it read?", "2/5  where may it write?", "[nowhere]", "5/5  memory cap, in MiB?", "[256]"):
            assert s in out, s
        p = load("t.json")
        assert p["files"]["write"] == ["/work/out"] and p["network"] == {"connect_tcp_ports": [443]}
        assert p["process"]["max_memory_mb"] == 64 and os.path.realpath(os.getcwd()) in p["files"]["read"]

    def test_new_refuses_to_overwrite_without_force(self, state, capsys):
        assert cli().run(["policy", "new", "t.json", "-y"]) == 0
        assert cli().run(["policy", "new", "t.json", "-y"]) == 2
        err = capsys.readouterr().err
        assert "t.json exists; nothing written" in err and "hint: --force" in err
        assert cli().run(["policy", "new", "t.json", "-y", "--force"]) == 0

    def test_new_with_a_bad_answer_writes_nothing(self, state, capsys):
        assert cli().run(["policy", "new", "t.json", "-y", "--read", "usr/"]) == 1
        assert not os.path.exists("t.json")
        assert "[no] files.read: 'usr/' must be an absolute path" in capsys.readouterr().out

    def test_edit_changes_one_edge_and_the_name(self, state, capsys):
        assert cli().run(["policy", "new", "t.json", "-y"]) == 0
        before = policy_hash(load("t.json"))
        capsys.readouterr()
        assert cli().run(["policy", "edit", "t.json", "--edge", "ports", "--value", "443"]) == 0
        out = capsys.readouterr().out
        after = policy_hash(load("t.json"))
        assert before != after and "renamed" in out and "a row changed, so the name changed" in out
        assert load("t.json")["network"] == {"connect_tcp_ports": [443]}

    def test_show_draws_the_three_boxes_the_hash_and_the_caveat(self, state, capsys):
        assert cli().run(["policy", "show", P2]) == 0
        out = capsys.readouterr().out
        for s in ("+- files", "+- network", "+- process", "write none", "memory  512 MiB", "pids    16",
                  policy_hash(load(P2)), "caveat", "a Boundary for the child"):
            assert s in out, s

    def test_check_marks_problems_on_the_drawing(self, state, capsys):
        with open("bad.json", "w") as f:
            json.dump({"pbp": 1, "id": "x", "files": {"read": ["usr/"]}, "network": "all"}, f)
        assert cli().run(["policy", "check", "bad.json"]) == 1
        out = capsys.readouterr().out
        assert "[no] files.read: 'usr/' must be an absolute path" in out and "2 problem(s)" in out

    def test_check_well_formed_gives_advice_and_the_run_command(self, state, capsys):
        assert cli().run(["policy", "check", P2]) == 0
        out = capsys.readouterr().out
        assert "well-formed v0 policy" in out and "advice" in out and "sharness-ai run --policy" in out

    def test_json_voice(self, state, capsys):
        assert cli().run(["--json", "policy", "show", P2]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["hash"] == policy_hash(load(P2)) and data["policy"]["id"] == "p2-tool-server"

    def test_missing_file_is_a_sentence_with_a_hint(self, state, capsys):
        assert cli().run(["policy", "hash", "nope.json"]) == 2
        err = capsys.readouterr().err
        assert "error: no such policy file: nope.json" in err and "hint: sharness-ai policy new nope.json" in err


class Test_Components:
    def test_map_names_all_seven_and_says_not_built(self, state, capsys):
        assert cli().run(["components"]) == 0
        out = capsys.readouterr().out
        for s in ("sharness.bash", "+- kms", "+- net", "+- launcher", "designed, not built", "policy: the manifest"):
            assert s in out, s

    def test_a_verb_shows_the_surface_and_exits_unavailable(self, state, capsys):
        assert cli().run(["kms"]) == EXIT_NOT_BUILT
        out = capsys.readouterr().out
        assert "+- KMS" in out and "POST /v0/unwrap" in out and "exits 69" in out
        assert cli().run(["net"]) == 0 and "runnable" in capsys.readouterr().out
        assert cli().run(["components", "kms"]) == EXIT_NOT_BUILT
        assert cli().run(["components", "fs"]) == 0 and "runnable" in capsys.readouterr().out

    def test_json_lists_them(self, state, capsys):
        assert cli().run(["--json", "components"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert set(data["components"]) == {"bash", "net", "kms", "fs", "llm", "launcher", "policy"}


class Test_Run_screen:
    @needs_landlock
    def test_plan_goes_to_stderr_and_the_tool_keeps_stdout(self, state, capfd):
        code = cli().run(["run", "--policy", P2, "--", "sh", "-c", "echo from-the-tool"])
        out, err = capfd.readouterr()
        assert code == 0 and out.strip() == "from-the-tool"
        for s in ("sharness-ai run  p2-tool-server", "enforced by", "not covered", "sh starts", "sh exit 0"):
            assert s in err, s

    @needs_landlock
    def test_quiet_leaves_only_the_tool(self, state, capfd):
        assert cli().run(["run", "--policy", P2, "--quiet", "--", "echo", "only"]) == 0
        out, err = capfd.readouterr()
        assert out.strip() == "only" and "enforced by" not in err

    def test_wrong_hash_prints_no_plan_and_a_hint(self, state, capsys):
        code = cli().run(["run", "--policy", P2, "--expect-hash", "sha256:0", "--", "true"])
        err = capsys.readouterr().err
        assert code == 125 and "starts" not in err and "hint:" in err

    def test_missing_policy_is_refused_with_a_hint(self, state, capsys):
        assert cli().run(["run", "--policy", "nope.json", "--", "true"]) == 125
        assert "hint: sharness-ai policy new nope.json" in capsys.readouterr().err


class Test_Hello_screen:
    def test_refuses_without_a_kernel_in_the_same_words(self, state, monkeypatch, capsys):
        monkeypatch.setattr(sys, "platform", "emscripten")
        assert cli().run(["hello"]) == 126
        out = capsys.readouterr().out
        assert "refused" in out and "Nothing ran" in out and "playground" in out

    def test_scoreboard_draws_measure(self, state, monkeypatch, capsys):
        from sharness_ai import hello as engine
        fake = {"experiment": "E04 hello", "policy_id": "hello", "policy_hash": "sha256:" + "a" * 64,
                "policy": {"pbp": 1, "id": "hello", "files": {"read": ["/usr"], "write": [], "exec": ["/usr"]},
                           "network": "none", "process": {"no_new_privs": True, "max_memory_mb": 128}},
                "landlock_abi": 7, "euid": 1000,
                "results": [{"probe": "read", "expected": "allowed", "got": "allowed", "exit": 0},
                            {"probe": "write-tmp", "expected": "refused", "got": "refused (PermissionError: EACCES)", "exit": 1},
                            {"probe": "net", "expected": "refused", "got": "inconclusive (timed out; the control failed too)", "exit": 1},
                            {"probe": "hash", "expected": "refused", "got": "refused", "exit": 125}],
                "held": 3, "inconclusive": 1, "failed": 0, "of": 4, "not_covered": "UDP", "report": "https://x"}
        monkeypatch.setattr(engine, "measure", lambda: fake)
        monkeypatch.setattr("sharness_ai.cli.CLI__Hello.unavailable", lambda: "")
        assert cli().run(["hello"]) == 0
        out = capsys.readouterr().out
        assert "[ok] read" in out and "refused by the kernel (EACCES)" in out and "[??] net" in out
        assert "refused by sharness-ai" in out and "3/4 held, 1 inconclusive" in out and "caveat" in out


class Test_Main:
    def test_debug_prints_the_trace_on_stderr(self, state, capsys):
        assert cli().run(["--debug", "policy", "hash", P2]) == 0
        out, err = capsys.readouterr()
        assert out.strip() == policy_hash(load(P2)) and "debug" in err and "total" in err

    def test_an_unexpected_error_is_a_sentence_unless_debug(self, state, monkeypatch, capsys):
        import sharness_ai.cli.CLI__Probe as m

        def boom():
            raise RuntimeError("kaboom")
        monkeypatch.setattr(m, "probe", boom)
        assert cli().run(["probe"]) == 1
        err = capsys.readouterr().err
        assert "error: RuntimeError in probe: kaboom" in err and "--debug" in err
        with pytest.raises(RuntimeError):
            cli().run(["--debug", "probe"])

    def test_translate_still_splits_the_wrapped_command(self, state, capsys):
        assert main(["policy", "translate", P2, "--to", "docker", "--", "my-tool", "--flag"]) == 0
        out = capsys.readouterr().out
        assert "docker run" in out and "my-tool --flag" in out and "not enforced" in out
