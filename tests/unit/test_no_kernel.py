"""In a runtime with no kernel (Pyodide, emscripten) run and hello refuse cleanly; probe says why."""
import sys

from sharness_ai import hello, probe, run


class Test_no_kernel:
    def test_unavailable_is_empty_here_or_says_why(self):
        reason = run.unavailable()
        if sys.platform.startswith("linux"):
            assert reason == ""

    def test_run_refuses_under_emscripten(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "platform", "emscripten")
        policy = {"pbp": 1, "id": "t", "files": {"read": [], "write": [], "exec": []}, "network": "none"}
        assert run.run(policy, ["/bin/true"]) == run.EXIT_APPLY
        err = capsys.readouterr().err
        assert "no kernel" in err and "Nothing ran" in err

    def test_hello_refuses_under_emscripten(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "platform", "emscripten")
        assert hello.hello() == run.EXIT_APPLY
        assert "refused" in capsys.readouterr().out

    def test_probe_render_has_no_none(self):
        p = probe.probe()
        p.update({"os": "emscripten", "no_new_privs": None, "seccomp": None, "cgroups": None,
                  "landlock_abi": 0, "caps_all": None, "cap_eff": None, "uid": 0})
        text = probe.render(p)
        assert "None" not in text
        assert "no kernel here" in text


class Test_hello_policy_paths:
    def test_virtualenv_prefix_is_readable_and_executable(self):
        """Python reads pyvenv.cfg from sys.prefix at start-up; without it every probe dies first."""
        import os
        p = hello.hello_policy()
        for key in ("read", "exec"):
            assert os.path.realpath(sys.prefix) in p["files"][key]
            assert os.path.realpath(sys.base_prefix) in p["files"][key]
