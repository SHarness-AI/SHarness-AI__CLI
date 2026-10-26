"""E09's build script: the cpio writer and the guest's pieces, without fetching or booting anything."""
import gzip
import importlib.util
import os
import struct
from pathlib import Path

import pytest

BROWSER = Path(__file__).resolve().parents[2] / "experiments" / "browser"
spec = importlib.util.spec_from_file_location("build_guest", BROWSER / "build_guest.py")
build_guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_guest)


def read_cpio(data: bytes):
    """A minimal newc reader: yields (name, mode, body)."""
    pos = 0
    while True:
        assert data[pos:pos + 6] == b"070701"
        fields = [int(data[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        name = data[pos + 110:pos + 110 + namesize - 1].decode()
        pos += 110 + namesize
        pos += (4 - pos % 4) % 4
        body = data[pos:pos + size]
        pos += size
        pos += (4 - pos % 4) % 4
        if name == "TRAILER!!!":
            return
        yield name, mode, body


class Test_cpio:
    def test_round_trip(self, tmp_path):
        root = tmp_path / "root"
        (root / "bin").mkdir(parents=True)
        (root / "bin" / "sh").write_bytes(b"#!/bin/busybox sh\n")
        (root / "bin" / "sh").chmod(0o755)
        (root / "init").write_text("echo hi\n")
        os.symlink("bin/sh", root / "sh")
        out = tmp_path / "initramfs.cpio.gz"
        build_guest.write_cpio(root, out)
        entries = {name: (mode, body) for name, mode, body in read_cpio(gzip.decompress(out.read_bytes()))}
        assert set(entries) == {"bin", "bin/sh", "init", "sh"}
        assert entries["bin/sh"][1] == b"#!/bin/busybox sh\n"
        assert entries["bin/sh"][0] & 0o777 == 0o755
        assert entries["sh"][1] == b"bin/sh"               # a symlink's body is its target
        assert entries["sh"][0] & 0o170000 == 0o120000

    def test_deterministic(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        (root / "a").write_text("a")
        os.utime(root / "a", (0, 0))
        os.utime(root, (0, 0))
        a, b = tmp_path / "a.gz", tmp_path / "b.gz"
        build_guest.write_cpio(root, a)
        build_guest.write_cpio(root, b)
        assert a.read_bytes() == b.read_bytes()


class Test_guest_pieces:
    def test_files_present(self):
        for name in ("init.sh", "page.html", "playground.html", "playground.js", "netwatch.js", "build_wheel.py", "test_playground.mjs",
                     "boot_node.mjs", "boot_browser.mjs", "chroot_native.sh", "package.json", "README.md"):
            assert (BROWSER / name).exists(), name

    def test_init_runs_policies_that_exist(self):
        init = (BROWSER / "init.sh").read_text()
        policies = BROWSER.parents[0] / "policies"
        import re
        for ref in set(re.findall(r"/work/policies/([\w.-]+\.json)", init)):
            assert (policies / ref).exists(), ref
        for marker in ("SHARNESS-GUEST-UP", "SHARNESS-HELLO-EXIT", "SHARNESS-DONE"):
            assert marker in init

    def test_kernel_is_pinned_with_landlock_note(self):
        assert build_guest.KERNEL_PACKAGE.startswith("linux-virt-6.")
        assert all("-r" in p for p in build_guest.PACKAGES)

    def test_v86_pinned_exactly(self):
        import json
        pkg = json.loads((BROWSER / "package.json").read_text())
        assert pkg["dependencies"]["v86"][0].isdigit(), "v86 must be pinned to an exact version"


spec_w = importlib.util.spec_from_file_location("build_wheel", BROWSER / "build_wheel.py")
build_wheel = importlib.util.module_from_spec(spec_w)
spec_w.loader.exec_module(build_wheel)


class Test_wheel:
    def test_wheel_is_valid_and_says_dev(self, tmp_path):
        import base64
        import hashlib
        import json
        import zipfile
        whl = build_wheel.build(tmp_path)
        ver = build_wheel.version()
        assert "+dev." in ver and whl.name == f"sharness_ai-{ver}-py3-none-any.whl"
        z = zipfile.ZipFile(whl)
        names = z.namelist()
        assert "sharness_ai/cli/CLI__Main.py" in names and "sharness_ai/ui/Draw.py" in names and "sharness_ai/policy.py" in names
        record = z.read(f"sharness_ai-{ver}.dist-info/RECORD").decode().splitlines()
        for row in record:
            name, digest, size = row.split(",")
            if digest:
                data = z.read(name)
                assert digest == "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                assert int(size) == len(data)
        assert z.read("sharness_ai/version").decode().strip() == "v" + ver
        manifest = json.loads((tmp_path / "wheel.json").read_text())
        assert manifest["wheel"] == whl.name and manifest["sha256"] == "sha256:" + hashlib.sha256(whl.read_bytes()).hexdigest()

    def test_playground_lists_policies_that_exist(self):
        import re
        js = (BROWSER / "playground.js").read_text()
        names = re.search(r"const POLICIES = \[(.*?)\];", js, re.S).group(1)
        for n in re.findall(r'"([\w-]+)"', names):
            assert (BROWSER.parent / "policies" / f"{n}.json").exists(), n
        assert "sharness.mode=shell" in js and "sharness.mode=shell" in (BROWSER / "init.sh").read_text()
