import json
import os

from sharness_ai.cli import main
from sharness_ai.policy import load
from sharness_ai.translate import TARGETS, translate

ROOT    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DENY    = os.path.join(ROOT, "experiments", "policies", "deny-all-example.json")
HTTPS   = os.path.join(ROOT, "experiments", "policies", "allow-https-example.json")


class Test_Translate:

    def test_every_target_returns_text_and_notes(self):
        policy = load(DENY)
        for target in TARGETS:
            text, notes = translate(policy, target, ("/bin/true",))
            assert text and isinstance(notes, list) and notes

    def test_bwrap_binds_follow_the_policy(self):
        text, notes = translate(load(DENY), "bwrap", ("/bin/true",))
        assert "--unshare-all" in text and "--ro-bind /usr /usr" in text and "--share-net" not in text
        text, notes = translate(load(HTTPS), "bwrap", ("/bin/true",))
        assert "--share-net" in text and any("connect_tcp_ports" in n for n in notes)

    def test_docker_network_and_caps(self):
        p = load(DENY)
        p["process"].update({"max_memory_mb": 64, "max_pids": 4})
        text, notes = translate(p, "docker", ("/bin/true",))
        assert "--network none" in text and "--memory 64m" in text and "--pids-limit 4" in text
        assert any("hash" in n for n in notes)

    def test_claude_code_settings_are_json_and_strict(self):
        text, notes = translate(load(DENY), "claude-code")
        s = json.loads(text)
        assert s["sandbox"]["enabled"] is True and s["sandbox"]["network"]["strictAllowlist"] is True
        assert s["sandbox"]["network"]["allowedDomains"] == []
        assert any("files.exec" in n for n in notes)

    def test_kubernetes_has_securitycontext_and_networkpolicy(self):
        text, notes = translate(load(HTTPS), "kubernetes", ("/bin/true",))
        assert "readOnlyRootFilesystem: true" in text and "kind: NetworkPolicy" in text and "port: 443" in text

    def test_cli_translate(self, capsys):
        assert main(["policy", "translate", DENY, "--to", "bwrap", "--", "/bin/true"]) == 0
        out = capsys.readouterr().out
        assert out.startswith("bwrap ") and "# bwrap: not enforced" in out
        assert main(["policy", "translate", DENY, "--to", "claude-code", "--notes"]) == 0
        assert "not enforced" in capsys.readouterr().out
