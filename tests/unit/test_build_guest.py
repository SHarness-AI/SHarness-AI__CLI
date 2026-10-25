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
        for name in ("init.sh", "page.html", "boot_node.mjs", "boot_browser.mjs", "chroot_native.sh", "package.json", "README.md"):
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
