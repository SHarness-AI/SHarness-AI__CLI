"""Resource caps (process.max_memory_mb, max_pids): RLIMIT_AS and RLIMIT_NPROC always; a cgroup
where /sys/fs/cgroup is writable. Needs Landlock like the rest of run."""
import os
import sys

import pytest

from sharness_ai import landlock, limits
from sharness_ai.hello import hello_policy
from sharness_ai.policy import check
from sharness_ai.run import run

needs_landlock = pytest.mark.skipif(landlock.abi() < 1, reason="Landlock is not available on this kernel")


def _py(code):
    return [sys.executable, "-I", "-c", code]


class Test_Policy_Caps:

    def test_caps_are_optional_non_negative_integers(self):
        base = hello_policy()
        assert check(base) == []
        base["process"]["max_memory_mb"] = 128
        base["process"]["max_pids"] = 4
        assert check(base) == []
        base["process"]["max_memory_mb"] = -1
        assert any("max_memory_mb" in x for x in check(base))
        base["process"]["max_memory_mb"] = True
        assert any("max_memory_mb" in x for x in check(base))

    def test_cgroup_version_is_known(self):
        assert limits.cgroup_version() in (0, 1, 2)


@needs_landlock
class Test_Run_Caps:

    def test_memory_cap_refuses_a_large_allocation(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        policy["process"]["max_memory_mb"] = 128
        assert run(policy, _py("b = bytearray(400 << 20); b[-1] = 1")) != 0
        assert run(policy, _py("b = bytearray(8 << 20); b[-1] = 1")) == 0

    def test_pids_cap_refuses_a_fork_beyond_it(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        policy["process"]["max_pids"] = 3
        code = ("import os, sys\n"
                "kids = []\n"
                "try:\n"
                "    for i in range(8):\n"
                "        pid = os.fork()\n"
                "        if pid == 0: os._exit(0)\n"
                "        kids.append(pid)\n"
                "except BlockingIOError:\n"
                "    sys.exit(3)\n"
                "finally:\n"
                "    for k in kids: os.waitpid(k, 0)\n")
        rc = run(policy, _py(code))
        assert rc in (3, 1, -9, 137), rc          # EAGAIN on fork (3), or the cgroup refused it

    def test_no_cgroup_left_behind(self, tmp_path):
        policy = hello_policy(workspace=str(tmp_path))
        policy["process"]["max_memory_mb"] = 64
        assert run(policy, _py("print(1)")) == 0
        for d in (f"{limits.CG}/{limits.NAME}", f"{limits.CG}/memory/{limits.NAME}"):
            if os.path.isdir(d):
                assert os.listdir(d) == []
