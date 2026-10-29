import json
import sys

from sharness_ai.probe import probe, render


class Test_Probe:

    def test_probe_reports_the_grant(self):
        p = probe()
        for k in ("os", "kernel", "python", "landlock_abi", "tools", "egress_proxy_vars", "memfd_secret"):
            assert k in p
        assert isinstance(p["landlock_abi"], int) and p["landlock_abi"] >= 0
        if sys.platform.startswith("linux"):
            assert p["uid"] is not None and p["namespaces"]

    def test_probe_never_prints_proxy_values(self, monkeypatch):
        monkeypatch.setenv("HTTPS_PROXY", "http://user:secret-value@127.0.0.1:3128")
        p = probe()
        text = render(p) + json.dumps(p)
        assert "HTTPS_PROXY" in text
        assert "secret-value" not in text


class Test_Issue_8:
    """Reported from a Linux Mint 22.3 guest (issue #8, 28 Oct 2026)."""

    def test_an_empty_effective_set_is_none_whatever_the_bounding_set(self):
        from sharness_ai.probe import caps_word
        assert caps_word({"caps_all": False, "cap_eff": "0000000000000000"}) == "none"
        assert caps_word({"caps_all": False, "cap_eff": "0000000000003000"}) == "some"
        assert caps_word({"caps_all": True, "cap_eff": "000001ffffffffff"}) == "all"
        assert caps_word({"caps_all": None, "cap_eff": None}) == "unknown"

    def test_a_refusal_names_the_error_not_the_runners_footer(self):
        from sharness_ai.hello import _classify
        err = "PermissionError: [Errno 13] Permission denied: '/tmp/x'\nnot covered: UDP and the rows it\n                  cannot enforce"
        got = _classify("write-tmp", 1, "", err)
        assert got.startswith("refused (PermissionError") and "cannot enforce" not in got
