"""In a runtime with no kernel (Pyodide, emscripten) run and hello refuse cleanly; probe says why."""
import sys

import pytest

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


class Test_other_os:
    """Issue #6: on macOS (and any OS that is not Linux) probe says what is missing, one row each, and
    run and hello refuse in one line. The platform is faked, so CI on Linux covers the text."""

    @pytest.fixture(params=[("darwin", "macOS"), ("freebsd14", "freebsd14")])
    def other(self, request, monkeypatch):
        monkeypatch.setattr(sys, "platform", request.param[0])
        return request.param[1]

    def test_probe_json_has_the_os_and_nulls(self, other):
        p = probe.probe()
        assert p["os"] == sys.platform and p["landlock_abi"] is None and p["memfd_secret"] is None
        assert p["cgroups"] is None and p["kernel_config"] is None and p["namespaces"] == []

    def test_probe_rows_say_not_applicable_and_why(self, other):
        text = probe.render(probe.probe())
        assert f"Landlock n/a ({other}: no Landlock)" in text and f"Seccomp n/a ({other}: no seccomp)" in text
        assert f"cgroups n/a ({other}: no cgroups)" in text and "None" not in text and "/proc/config.gz" not in text
        assert f"reading     {other}: the grant is everything" in text

    def test_probe_screen_says_the_same(self, other, capsys, tmp_path):
        from sharness_ai.cli import CLI__Main
        from sharness_ai.ui import Term
        assert CLI__Main(term=Term.plain(width=200), state_path=str(tmp_path / "state.json")).run(["probe"]) == 0
        out = " ".join(capsys.readouterr().out.split())
        assert f"Landlock n/a ({other}: no Landlock)" in out and "None" not in out
        assert f"{other}: the grant is everything this user may do" in out

    def test_run_refuses_in_one_line(self, other, capsys):
        policy = {"pbp": 1, "id": "t", "files": {"read": [], "write": [], "exec": []}, "network": "none"}
        assert run.run(policy, ["/bin/true"]) == run.EXIT_APPLY
        err = capsys.readouterr().err.strip()
        assert len(err.splitlines()) == 1 and f"this is {other}: no Landlock" in err and err.endswith("Nothing ran.")

    def test_hello_refuses(self, other, capsys):
        assert hello.hello() == run.EXIT_APPLY
        assert other in capsys.readouterr().out
