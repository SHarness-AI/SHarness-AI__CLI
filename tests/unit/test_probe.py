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

