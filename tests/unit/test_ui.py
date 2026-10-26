"""The drawing layer: one screen, two glyph sets, deterministic at a fixed width."""
import os

from sharness_ai.ui import Draw, Prompt, Term, Trace

POLICY = {"pbp": 1, "id": "t", "files": {"read": ["/usr", "/lib", "/etc", "/work"], "write": ["/work/out"],
                                           "exec": ["/usr", "/lib"]},
          "network": {"connect_tcp_ports": [443]}, "process": {"no_new_privs": True, "max_memory_mb": 256}}


class Test_Term:
    def test_plain_is_ascii_without_colour(self):
        t = Term.plain(width=80)
        assert t.glyph("ok") == "[ok]" and t.glyph("tl") == "+" and t.style("x", "ok") == "x"
        assert not t.interactive

    def test_detect_on_a_pipe_is_not_interactive_and_has_no_colour(self, monkeypatch):
        monkeypatch.setenv("TERM", "xterm")
        t = Term.detect()                      # pytest's stdout is a capture, not a tty
        assert not t.interactive and not t.color

    def test_env_forces_plain(self, monkeypatch):
        monkeypatch.setenv("SHARNESS_AI_PLAIN", "1")
        assert not Term.detect().unicode

    def test_width_is_clamped(self):
        assert Term.detect(width=5).width == 40 and Term.detect(width=9999).width == 200

    def test_shorten_keeps_both_ends(self):
        t = Term.plain()
        s = t.shorten("sha256:" + "a" * 64, 19)
        assert len(s) == 19 and s.startswith("sha256:a") and s.endswith("a")


class Test_Draw:
    def test_box_edges_line_up_in_both_glyph_sets(self):
        for unicode in (False, True):
            d = Draw(Term(width=80, unicode=unicode))
            lines = d.box("files", ["read /usr", "write /work/out"])
            assert len({len(x) for x in lines}) == 1, lines

    def test_beside_fits_or_stacks(self):
        d = Draw(Term.plain(width=100))
        wide = Draw(Term.plain(width=40))
        a, b = d.box("a", ["x" * 20]), d.box("b", ["y" * 20])
        assert len(d.beside([a, b])) == 3            # side by side: three rows
        assert len(wide.beside([a, b])) == 6         # stacked

    def test_policy_drawing_names_every_edge_and_the_hash(self):
        d = Draw(Term.plain(width=110))
        text = "\n".join(d.policy(POLICY, "sha256:" + "0" * 64))
        for s in ("files", "network", "process", "read  /usr /lib /etc /work", "write /work/out", "connect_tcp  443",
                  "UDP is not covered", "memory  256 MiB", "pids    no cap", "sha256:" + "0" * 64):
            assert s in text, s

    def test_paths_never_cut_inside_a_path(self):
        d = Draw(Term.plain())
        assert d.paths(["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"], 14) == "/usr /lib +4"
        assert d.paths([], 14) == "none"

    def test_kv_wraps_under_its_label_and_a_long_label_keeps_a_space(self):
        d = Draw(Term.plain(width=60))
        lines = d.kv("label", "word " * 30)
        assert all(len(x) <= 60 for x in lines) and lines[1].startswith(" " * 18)
        assert d.kv("sharness.launcher", "the bootstrap")[0] == "  sharness.launcher the bootstrap"

    def test_kv_does_not_break_a_url(self):
        d = Draw(Term.plain(width=60))
        url = "https://github.com/SHarness-AI/SHarness-AI__CLI/issues/new?template=hello-report.yml"
        assert any(url in x for x in d.kv("report", "paste it at " + url + " please"))

    def test_bar_and_banner(self):
        d = Draw(Term.plain(width=80))
        assert d.bar(3, 6, 12) == "######......"
        assert len(d.banner("v0.1.0")) == 5 and "sharness-ai v0.1.0" in d.banner("v0.1.0")[2]
        assert len(Draw(Term.plain(width=60)).banner("v0.1.0")) == 1

    def test_row_has_mark_what_target_result(self):
        d = Draw(Term.plain())
        assert d.row("no", "write", "/work/out/x", "refused by the kernel", "EACCES") == \
            "  [no] write     /work/out/x                  refused by the kernel  EACCES"


class Test_Prompt:
    def test_scripted_answers_then_defaults(self, capsys):
        p = Prompt(Term.plain(), answers=["443"])
        assert p.ask("ports?", default="none") == "443"
        assert p.ask("memory?", default="256") == "256"        # nobody left to answer: the default
        assert p.choose("edge?", [("read", "r"), ("write", "w")], default="write") == "write"
        assert p.confirm("ok?", default=False) is False

    def test_an_unknown_choice_falls_back_when_nobody_can_answer(self, capsys):
        p = Prompt(Term.plain(), answers=["nope"])
        assert p.choose("edge?", [("read", "r"), ("write", "w")], default="read") == "read"
        assert "not one of" in capsys.readouterr().out


class Test_Trace:
    def test_records_only_when_enabled(self):
        off, on = Trace(), Trace(enabled=True)
        with off.step("a"):
            pass
        with on.step("b"):
            pass
        on.note("n")
        assert off.steps == [] and [s[0] for s in on.steps] == ["b", "note"]
        assert on.render(Term.plain())[1].endswith("b") and off.render(Term.plain()) == []
