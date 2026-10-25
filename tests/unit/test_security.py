"""Security tests: each pins a finding from the review of 25 Oct 2026 (sharness.ai/security).
A test here failing means a hole the review closed has opened again."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from sharness_ai import landlock, limits, policy, translate
from sharness_ai.hello import PROBE_FLAGS, RUNNER_FLAGS, hello_policy
from sharness_ai.run import EXIT_APPLY, EXIT_REFUSED, limits_plan, network_plan, resolved_elsewhere, run

ROOT = Path(__file__).resolve().parents[2]
needs_landlock = pytest.mark.skipif(landlock.abi() < 1, reason="Landlock is not available on this kernel")


def _py(code):
    return [sys.executable, "-I", "-c", code]


class Test_Policy_Shape:
    """What the person reads must be what the kernel binds."""

    def test_paths_must_be_normalised(self):
        for bad in ("/usr/../etc", "/usr/", "//usr", "/usr/./bin", "/usr//bin", "relative", ""):
            assert policy.path_problem(bad), bad
        for ok in ("/", "/usr", "/work/out", "/tmp/a b"):
            assert policy.path_problem(ok) == "", ok

    def test_paths_with_control_characters_are_refused(self):
        assert policy.path_problem("/work\n  - name: evil")
        assert policy.path_problem("/work\x00")

    def test_ports_cannot_be_booleans(self):
        p = hello_policy()
        p["network"] = {"connect_tcp_ports": [True]}
        assert any("connect_tcp_ports" in x for x in policy.check(p))

    def test_id_is_bounded_and_printable(self):
        p = hello_policy()
        p["id"] = "x" * 201
        assert any("id" in x for x in policy.check(p))
        p["id"] = "a\nb"
        assert any("id" in x for x in policy.check(p))

    def test_duplicate_keys_are_refused(self, tmp_path):
        f = tmp_path / "dup.json"
        f.write_text('{"pbp": 1, "id": "a", "id": "b"}')
        with pytest.raises(policy.PolicyError, match="duplicate key"):
            policy.load(f)

    def test_oversized_file_is_refused(self, tmp_path):
        f = tmp_path / "big.json"
        f.write_text('{"notes": "' + "x" * (policy.MAX_FILE_SIZE + 10) + '"}')
        with pytest.raises(policy.PolicyError, match="larger"):
            policy.load(f)


class Test_Hash_Agreement:
    """Where Python and JavaScript would hash differently, refuse rather than differ."""

    def test_integers_beyond_2_53_are_refused(self):
        assert policy.canonical({"a": policy.MAX_SAFE_INT}) == b'{"a":9007199254740991}'
        with pytest.raises(policy.PolicyError, match="JavaScript"):
            policy.canonical({"a": policy.MAX_SAFE_INT + 1})
        with pytest.raises(policy.PolicyError):
            policy.canonical({"a": 10 ** 21})

    def test_lone_surrogates_are_refused_not_a_traceback(self):
        with pytest.raises(policy.PolicyError, match="surrogate"):
            policy.canonical({"id": "\ud800"})

    def test_the_browser_canonicaliser_agrees_on_the_examples(self):
        """The same algorithm as playground.js canon(), run in Node when Node is present."""
        node = __import__("shutil").which("node")
        if not node:
            pytest.skip("no node")
        js = (ROOT / "experiments/browser/playground.js").read_text()
        fn = re.search(r"function canon\(v\) \{.*?\n\}", js, re.S).group(0)
        for f in sorted((ROOT / "experiments/policies").glob("*.json")):
            text = f.read_text(encoding="utf-8")
            out = subprocess.run([node, "-e", fn + f"\nprocess.stdout.write(canon(JSON.parse({json.dumps(text)})))"],
                                 capture_output=True, text=True, check=True).stdout
            assert out.encode("utf-8") == policy.canonical(json.loads(text)), f.name


class Test_Enforcement_Plan:
    """Rows that cannot be enforced are refusals, not silence."""

    def test_network_none_without_namespace_or_tcp_rules_is_refused(self):
        refusals, gaps = network_plan("none", abi=1, netns="")
        assert refusals and "network none" in refusals[0]
        refusals, gaps = network_plan("none", abi=4, netns="")
        assert not refusals and any("UDP" in g for g in gaps)
        refusals, gaps = network_plan("none", abi=7, netns="netns")
        assert not refusals and any("Unix" in g for g in gaps)

    def test_ports_without_tcp_rules_are_refused(self):
        refusals, _ = network_plan({"connect_tcp_ports": [443]}, abi=3, netns="")
        assert refusals and "443" in refusals[0]
        assert not network_plan({"connect_tcp_ports": [443]}, abi=4, netns="")[0]

    def test_max_pids_as_root_without_a_cgroup_is_refused(self):
        refusals, _ = limits_plan(None, 4, cgroup_applied=[], euid=0)
        assert refusals and "max_pids" in refusals[0]
        assert not limits_plan(None, 4, cgroup_applied=["cgroup2 pids.max=4"], euid=0)[0]
        assert not limits_plan(None, 4, cgroup_applied=[], euid=1000)[0]

    def test_nproc_does_not_bind_root(self):
        assert limits.nproc_binds(0) is False and limits.nproc_binds(1000) is True

    def test_write_access_never_includes_execute(self):
        for abi in range(1, 8):
            assert not landlock.access_write(landlock.fs_access_for(abi)) & landlock.FS_EXECUTE
            assert landlock.access_write(landlock.fs_access_for(abi)) & landlock.FS_WRITE_FILE


@needs_landlock
class Test_Enforcement_Under_Landlock:

    def test_a_writable_path_is_not_executable(self, tmp_path):
        script = tmp_path / "x.sh"
        script.write_text("#!/bin/sh\necho ran\n")
        script.chmod(0o755)
        p = hello_policy(workspace=str(tmp_path))
        p["files"]["write"] = [str(tmp_path)]
        assert run(p, [str(script)]) == EXIT_APPLY            # execve refused: EACCES before anything ran
        assert run(p, _py(f"open({str(tmp_path / 'y')!r}, 'w').write('ok')")) == 0   # still writable

    def test_a_symlinked_writable_path_is_refused_before_anything_runs(self, tmp_path):
        (tmp_path / "out").symlink_to(tmp_path.parent)
        p = hello_policy(workspace=str(tmp_path))
        p["files"]["write"] = [str(tmp_path / "out")]
        assert resolved_elsewhere(p) == [(str(tmp_path / "out"), str(tmp_path.parent))]
        marker = tmp_path.parent / "escaped"
        assert run(p, _py(f"open({str(marker)!r}, 'w')")) == EXIT_REFUSED
        assert not marker.exists()

    def test_a_symlinked_read_path_is_allowed_and_reported(self, tmp_path):
        p = hello_policy(workspace=str(tmp_path))
        (tmp_path / "link").symlink_to("/usr")
        p["files"]["read"].append(str(tmp_path / "link"))
        assert resolved_elsewhere(p) == []
        assert run(p, _py("import os; os.listdir('/usr')")) == 0

    def test_inherited_descriptors_are_closed(self, tmp_path):
        leak = tmp_path / "leak"
        fd = os.open(leak, os.O_WRONLY | os.O_CREAT)
        os.set_inheritable(fd, True)
        try:
            p = hello_policy(workspace=str(tmp_path))
            assert run(p, _py(f"import os; os.write({fd}, b'leaked')")) != 0
            assert leak.stat().st_size == 0
        finally:
            os.close(fd)

    def test_best_effort_runs_and_says_so(self, tmp_path, monkeypatch, capfd):
        monkeypatch.setattr(limits, "cgroup", lambda pid, m, n: ([], None))
        p = hello_policy(workspace=str(tmp_path))
        p["process"]["max_pids"] = 4
        if os.geteuid() != 0:
            pytest.skip("the refusal is for uid 0 without a cgroup")
        assert run(p, _py("print('ran')")) == EXIT_APPLY
        assert "max_pids" in capfd.readouterr().err
        assert run(p, _py("print('ran')"), best_effort=True) == 0
        assert "NOT enforced" in capfd.readouterr().err

    def test_unix_socket_gap_is_declared(self, tmp_path, capfd):
        """Known and declared, not fixed: Landlock has no rule for Unix sockets by path."""
        p = hello_policy(workspace=str(tmp_path))
        assert run(p, _py("print(1)")) == 0
        assert "Unix-domain sockets" in capfd.readouterr().err


class Test_Hello_Runner:

    def test_runner_and_probes_do_not_import_from_the_workspace(self):
        assert "-P" in RUNNER_FLAGS and "-s" in RUNNER_FLAGS
        assert "-I" in PROBE_FLAGS

    def test_a_planted_package_in_the_workspace_is_not_imported(self, tmp_path):
        shadow = tmp_path / "sharness_ai"
        shadow.mkdir()
        (shadow / "__init__.py").write_text("raise SystemExit('SHADOWED')\n")
        (shadow / "__main__.py").write_text("")
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        r = subprocess.run([sys.executable, *RUNNER_FLAGS, "-m", "sharness_ai", "--version"],
                           cwd=tmp_path, capture_output=True, text=True, env=env)
        assert r.returncode == 0 and r.stdout.startswith("sharness-ai v"), r.stderr


class Test_Translate_Output:

    def test_kubernetes_quotes_paths(self):
        p = policy.load(ROOT / "experiments/policies/p3-newsroom-agent.json")
        p["files"]["write"] = ["/work/out\n  - name: evil"]      # check() would refuse this; translate must not trust it
        text, _ = translate.translate(p, "kubernetes", ("/bin/true",))
        assert 'mountPath: "/work/out\\n  - name: evil"' in text
        assert "\n  - name: evil" not in text

    def test_shell_lines_are_quoted(self):
        p = policy.load(ROOT / "experiments/policies/p1-agent-session.json")
        text, _ = translate.translate(p, "bwrap", ("/bin/sh", "-c", "echo $(id)"))
        assert "'echo $(id)'" in text
        text, _ = translate.translate(p, "docker", ("/bin/sh", "-c", "echo $(id)"))
        assert "'echo $(id)'" in text


class Test_Advice:

    def test_advice_names_the_known_gaps(self):
        a = "\n".join(policy.advice(policy.load(ROOT / "experiments/policies/p1-agent-session.json")))
        for s in ("/tmp", "exec '/etc'", "ports, not hosts", "environment"):
            assert s in a
        p = hello_policy()
        p["files"]["write"] = ["/work"]
        p["files"]["exec"].append("/work")
        assert any("writable and" in x for x in policy.advice(p))


class Test_Repository_Hygiene:
    """Checks a contributor can run with the standard library, so they run everywhere CI does."""

    WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.yml"))

    def test_every_action_is_pinned_to_a_commit(self):
        for wf in self.WORKFLOWS:
            for line in wf.read_text().splitlines():
                m = re.search(r"^\s*-?\s*uses:\s*([^\s#]+)", line)
                if m and not m.group(1).startswith("./"):
                    assert re.search(r"@[0-9a-f]{40}(\s|$)", line), f"{wf.name}: {line.strip()} is not pinned to a commit"

    def test_every_workflow_declares_minimal_permissions(self):
        for wf in self.WORKFLOWS:
            text = wf.read_text()
            assert re.search(r"^permissions:\s*$", text, re.M), f"{wf.name}: no top-level permissions block"
            assert "pull_request_target" not in text, f"{wf.name}: pull_request_target runs with the base repo's secrets"
            assert "write-all" not in text, wf.name

    def test_no_untrusted_expression_in_run_steps(self):
        risky = re.compile(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.[^}]*(title|body|message|name)")
        for wf in self.WORKFLOWS:
            assert not risky.search(wf.read_text()), f"{wf.name}: an event field is interpolated into a script"

    def test_no_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text()
        deps = re.search(r"\[tool\.poetry\.dependencies\](.*?)\n\[", text, re.S).group(1)
        assert [l for l in deps.strip().splitlines() if l.strip()] == ['python = ">=3.11"'], deps

    def test_no_secret_shaped_strings_in_the_tree(self):
        shapes = [re.compile(s) for s in (
            r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9_]{22,}", r"gh[ousr]_[A-Za-z0-9]{36}",
            r"sk-ant-[A-Za-z0-9_-]{20,}", r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----", r"xox[baprs]-[A-Za-z0-9-]{10,}",
            r"[A-Za-z0-9_-]{20,}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")]
        files = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
        for rel in files:
            f = ROOT / rel
            if f.suffix in (".png", ".jpg", ".webp", ".gz", ".bin", ".wasm", ".whl"):
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
            for s in shapes:
                assert not s.search(text), f"{rel}: contains a secret-shaped string ({s.pattern})"

    def test_guest_build_pins_every_download(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_guest", ROOT / "experiments/browser/build_guest.py")
        bg = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bg)
        for name in list(bg.PACKAGES) + [bg.KERNEL_PACKAGE]:
            assert re.fullmatch(r"[0-9a-f]{64}", bg.SHA256.get(name + ".apk", "")), f"{name}: no sha256 pinned"
        for name in bg.BIOS:
            assert re.fullmatch(r"[0-9a-f]{64}", bg.SHA256.get(name, "")), name
        assert re.fullmatch(r"[0-9a-f]{40}", bg.V86_COMMIT)
        assert "master" not in bg.V86_RAW

    def test_static_server_refuses_path_traversal(self):
        js = (ROOT / "experiments/browser/boot_browser.mjs").read_text()
        assert "startsWith(WWW" in js and "normalize(" in js
