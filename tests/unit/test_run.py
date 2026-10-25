"""E03 and E04 under test. These need Linux with Landlock; elsewhere they are skipped, and
the policy and probe tests still run."""
import json
import os
import subprocess
import sys

import pytest

from sharness_ai import landlock
from sharness_ai.hello import hello_policy
from sharness_ai.policy import policy_hash
from sharness_ai.run import EXIT_REFUSED, plan, run

ABI = landlock.abi()
needs_landlock = pytest.mark.skipif(ABI < 1, reason="Landlock is not available on this kernel")


def _py(code):
    return [sys.executable, "-I", "-c", code]


class Test_Landlock_Module:

    def test_abi_is_an_int(self):
        assert isinstance(ABI, int) and ABI >= 0

    def test_fs_access_grows_with_the_abi(self):
        assert landlock.fs_access_for(1) == (1 << 13) - 1
        assert landlock.fs_access_for(3) & landlock.FS_TRUNCATE
        assert not landlock.fs_access_for(2) & landlock.FS_TRUNCATE
        assert landlock.fs_access_for(5) & landlock.FS_IOCTL_DEV

    def test_plan_matches_the_kernel(self):
        p = plan(hello_policy())
        assert p["landlock_abi"] == ABI
        assert p["landlock_tcp"] == (ABI >= 4)


class Test_Run_Refusals:

    def test_wrong_expect_hash_runs_nothing(self, tmp_path):
        marker = tmp_path / "ran"
        policy = hello_policy(workspace=str(tmp_path))
        rc = run(policy, _py(f"open({str(marker)!r}, 'w').close()"), expect_hash="sha256:" + "0" * 64)
        assert rc == EXIT_REFUSED
        assert not marker.exists()

    def test_malformed_policy_runs_nothing(self):
        assert run({"pbp": 1}, _py("print(1)")) == EXIT_REFUSED

    def test_no_command_is_refused(self):
        assert run(hello_policy(), []) == EXIT_REFUSED


@needs_landlock
class Test_Run_Under_Landlock:

    def test_read_allowed_write_denied(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        assert run(policy, _py("import os; os.listdir('/usr')")) == 0
        rc = run(policy, _py(f"open({str(tmp_path / 'x')!r}, 'w')"))
        assert rc != 0 and not (tmp_path / "x").exists()

    def test_write_allowed_where_the_policy_says(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        policy["files"]["write"] = [str(tmp_path)]
        assert run(policy, _py(f"open({str(tmp_path / 'y')!r}, 'w').write('ok')")) == 0
        assert (tmp_path / "y").read_text() == "ok"

    def test_the_child_sees_the_policy_hash(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        policy["files"]["write"] = [str(tmp_path)]
        out = tmp_path / "env"
        assert run(policy, _py(f"import os; open({str(out)!r}, 'w').write(os.environ['SHARNESS_AI_POLICY_HASH'])")) == 0
        assert out.read_text() == policy_hash(policy)

    @pytest.mark.skipif(ABI < 4 and os.geteuid() != 0, reason="no TCP enforcement: Landlock ABI < 4 and not root")
    def test_tcp_connect_denied_with_network_none(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        rc = run(policy, _py("import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)"))
        assert rc != 0


@needs_landlock
class Test_Hello:

    def test_hello_json_holds(self, tmp_path):
        r = subprocess.run([sys.executable, "-m", "sharness_ai", "hello", "--json"],
                           cwd=tmp_path, capture_output=True, text=True, timeout=120)
        assert r.returncode in (0, 1), r.stderr
        data = json.loads(r.stdout)
        got = {x["probe"]: x["got"] for x in data["results"]}
        assert got["read"] == "allowed"
        assert got["write-tmp"].startswith("refused")
        assert got["write-cwd"].startswith("refused")
        assert got["hash"] == "refused"
        if ABI >= 4 or os.geteuid() == 0:
            assert got["net"].startswith("refused")
            assert got["memory"].startswith("refused")
            assert r.returncode == 0 and data["held"] == data["of"] == 6
