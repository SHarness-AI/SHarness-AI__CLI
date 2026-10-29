from sharness_ai import hello
from sharness_ai.probe import caps_label

FOOTER = ("── python3 exit 1 · 0.1 s ──\n"
          "  next            sharness-ai policy translate hello.json --to docker --\n"
          "                  CMD carries the same policy to another enforcer,\n"
          "                  with what it cannot enforce")


class Test_Classify_Reason:

    def test_refusal_names_the_error_not_the_footer(self):
        err = "Traceback (most recent call last):\nPermissionError: [Errno 13] Permission denied: '/tmp/x'\n" + FOOTER
        got = hello._classify("write-tmp", 1, "", err)
        assert got.startswith("refused (PermissionError")
        assert "cannot enforce" not in got

    def test_memory_error(self):
        got = hello._classify("memory", 1, "", "Traceback ...\nMemoryError\n" + FOOTER)
        assert got == "refused (MemoryError)"


class Test_Caps_Label:

    def test_no_effective_caps_with_full_bounding_set(self):
        p = {"cap_eff": "0000000000000000", "cap_bnd": "000001ffffffffff", "caps_all": True}
        assert caps_label(p).startswith("none in effect")
        assert "bounding set full" in caps_label(p)

    def test_root(self):
        p = {"cap_eff": "000001fffeffffff", "cap_bnd": "000001fffeffffff", "caps_all": True}
        assert caps_label(p).startswith("all in effect")

    def test_unknown(self):
        assert caps_label({"cap_eff": None, "cap_bnd": None, "caps_all": None}) == "unknown"
