"""The shell launcher: the plan (the proxy's port as the only network row), the processes of a uid, the
live page and its event stream, and, as root with Landlock, a command under a unique uid."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

import pytest

from sharness_ai import landlock
from sharness_ai.launcher import Launcher
from sharness_ai.launcher.UI import UI
from sharness_ai.launcher.Watch import processes
from sharness_ai.door.Verdict import Audit, Verdict

needs_openssl = pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")


class Test_plan:
    def test_compile_replaces_the_network_row_with_the_proxy_port(self, tmp_path):
        la = Launcher(str(tmp_path), ["github.com", "pypi.org"], unique_uid=False, ui=False)
        v0 = la.compile(31337)
        assert v0["network"] == {"connect_tcp_ports": [31337]} and str(tmp_path) in v0["files"]["write"]
        assert la.chain.top.notes[0].startswith("contain shell to ")
        from sharness_ai.policy import check
        assert not check(v0)


class Test_watch:
    def test_finds_this_process(self):
        me = [p for p in processes(os.geteuid()) if p["pid"] == os.getpid()]
        assert me and "python" in me[0]["cmd"].lower() and me[0]["rss_kb"] > 0


class Test_UI:
    def test_page_and_events(self):
        audit = Audit("sharness.net.proxy")
        audit.record("uid 1", "CONNECT", "example.com:443", 0, Verdict.refuse("example.com is not on the allowlist", "hosts"))
        state = {"uid": os.geteuid(), "proxy_port": 1, "hosts": ["github.com"], "workspace": "/w", "door_port": 2}
        ui = UI(state, [audit], uid=os.geteuid())
        url = ui.serve()
        try:
            page = urllib.request.urlopen(url, timeout=5).read().decode()  # noqa: S310 - a loopback http URL the test just made
            assert "sharness-ai shell" in page and "decisions" in page
            with urllib.request.urlopen(url + "events", timeout=5) as r:  # noqa: S310
                line = r.readline().decode()
            data = json.loads(line[len("data: "):])
            assert data["refused"] == 1 and data["traffic"][0]["path"] == "example.com:443" and data["processes"]
        finally:
            ui.stop()


class Test_shell:
    @needs_openssl
    @pytest.mark.skipif(landlock.abi() < 1 or os.geteuid() != 0 or not shutil.which("useradd"), reason="needs root, Landlock and useradd")
    def test_a_command_runs_as_a_unique_uid_with_the_proxy_as_its_only_port(self, tmp_path):
        import tempfile
        base = Path(tempfile.mkdtemp(prefix="sharness-shell-test-", dir="/tmp"))   # noqa: S108 - pytest's own tmp is 0700, which the new uid cannot enter
        os.chmod(base, 0o755)                                                        # noqa: S103 - the point: a workspace the shell's uid can enter
        work = base / "work"
        work.mkdir()
        os.chmod(work, 0o777)                                                        # noqa: S103 - and write
        r = subprocess.run([sys.executable, "-m", "sharness_ai", "--plain", "--width", "120", "shell", "--workspace", str(work), "--sites", "localhost",
                            "--no-ui", "--", "sh", "-c", "id -u; echo $HTTPS_PROXY; touch /etc/x 2>/dev/null || echo refused; echo hi > n.txt && echo wrote"],
                           capture_output=True, text=True, timeout=120, env={**os.environ, "SHARNESS_AI_STATE": str(tmp_path / "st.json")})
        out = r.stdout
        assert "made for this shell" in out, (out, r.stderr)
        uid_line = [x for x in out.splitlines() if x.strip().isdigit()]
        assert uid_line and int(uid_line[0]) != 0, out
        assert "http://127.0.0.1:" in out and "refused" in out and "wrote" in out and (work / "n.txt").read_text() == "hi\n"
        shutil.rmtree(base, ignore_errors=True)
