#!/usr/bin/env python3
"""E09: build the Alpine x86 guest that runs sharness-ai under a real Linux kernel in v86.

Standard library only. The result is a kernel and an initramfs that v86 boots in Node and in
a browser tab (boot_node.mjs, boot_browser.mjs), and a rootfs the host kernel can chroot into
(chroot_native.sh). Nothing here is a SHarness component: it is the test bench for E01, E03
and E04 on a second kernel, one that anyone can run without installing anything.

    python3 experiments/browser/build_guest.py [--out DIR] [--cache DIR] [--no-www]

Steps: fetch the pinned Alpine 3.23 x86 packages (busybox, musl, python3 and what they need,
and linux-virt, whose kernel is built with Landlock); unpack them with tarfile; add the
sharness_ai package from this checkout and the example policies; write /init (init.sh);
pack a newc cpio, gzipped; copy the kernel, the initramfs, v86 (from node_modules) and the
BIOS files into www/ next to the page. Re-running only fetches what the cache lacks.
"""
import argparse
import gzip
import hashlib
import io
import os
import shutil
import stat
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]

ALPINE = "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86/"
# Resolved from APKINDEX on 25 Oct 2026 for: python3 busybox musl alpine-baselayout linux-virt.
# Pinned so the guest is the same every time; bump deliberately, with the date, in README.md.
PACKAGES = [
    "alpine-baselayout-3.7.2-r0", "alpine-baselayout-data-3.7.2-r0",
    "busybox-1.37.0-r30", "busybox-binsh-1.37.0-r30", "musl-1.2.5-r24",
    "python3-3.12.15-r0", "libffi-3.5.2-r0", "libexpat-2.9.0-r0", "libbz2-1.0.8-r6",
    "gdbm-1.26-r0", "xz-libs-5.8.4-r0", "mpdecimal-4.0.1-r0", "zlib-1.3.2-r1",
    "libssl3-3.5.9-r0", "libcrypto3-3.5.9-r0", "sqlite-libs-3.53.4-r0", "readline-8.3.1-r0",
    "libncursesw-6.5_p20251123-r0", "ncurses-terminfo-base-6.5_p20251123-r0",
    "libpanelw-6.5_p20251123-r0", "libgcc-15.2.0-r2", "libstdc++-15.2.0-r2",
]
KERNEL_PACKAGE = "linux-virt-6.18.58-r0"      # CONFIG_SECURITY_LANDLOCK=y, landlock first in CONFIG_LSM

# v86 ships its BIOS images in the repository, not in the npm package.
V86_RAW = "https://raw.githubusercontent.com/copy/v86/master/bios/"
BIOS = {   # sha256 as fetched on 25 Oct 2026; a change is reported, not refused
    "seabios.bin": "73e3f359102e3a9982c35fce98eb7cd08f18303ac7f1ba6ebfbe6cdc1c244d98",
    "vgabios.bin": "a4bc0d80cc3ca028c73dafa8fee396b8d054ce87ebd8abfbd31b06b437607880",
}
APK_META = (".PKGINFO", ".SIGN.", ".post-", ".pre-", ".trigger")


def fetch(url: str, dest: Path):
    if dest.exists():
        return
    print(f"  fetch {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f)
    tmp.rename(dest)


def unpack_apk(apk: Path, root: Path):
    """An .apk is concatenated gzip streams of tar: tarfile reads them as one archive."""
    with tarfile.open(apk, "r:gz") as t:
        members = [m for m in t.getmembers()
                   if not m.name.startswith(APK_META) and ".." not in m.name.split("/")]
        for m in members:
            if m.isdev():               # devtmpfs provides device nodes; a cpio of them needs root
                continue
            try:
                t.extract(m, root, set_attrs=True, filter="tar")
            except TypeError:           # Python < 3.12 has no filter argument
                t.extract(m, root, set_attrs=True)


def write_cpio(root: Path, out: Path):
    """Pack a tree as a gzipped 'newc' cpio, the initramfs format the kernel unpacks itself."""
    buf = io.BytesIO()
    ino = 0

    def entry(name: str, mode: int, mtime: int, data: bytes = b""):
        nonlocal ino
        ino += 1
        fields = [ino, mode, 0, 0, 1, mtime, len(data), 0, 0, 0, 0, len(name) + 1, 0]
        rec = b"070701" + "".join("%08X" % v for v in fields).encode() + name.encode() + b"\0"
        rec += b"\0" * ((4 - len(rec) % 4) % 4) + data
        rec += b"\0" * ((4 - len(rec) % 4) % 4)
        buf.write(rec)

    for dirpath, dirs, files in os.walk(root):
        dirs.sort()
        for name in dirs + sorted(files):
            full = Path(dirpath, name)
            rel = full.relative_to(root).as_posix()
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                entry(rel, st.st_mode, int(st.st_mtime), os.readlink(full).encode())
            elif stat.S_ISDIR(st.st_mode):
                entry(rel, st.st_mode, int(st.st_mtime))
            elif stat.S_ISREG(st.st_mode):
                entry(rel, st.st_mode, int(st.st_mtime), full.read_bytes())
    entry("TRAILER!!!", 0, 0)
    out.write_bytes(gzip.compress(buf.getvalue(), compresslevel=6, mtime=0))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=HERE / "out", help="where rootfs/, kernel, initramfs and www/ go")
    ap.add_argument("--cache", type=Path, default=HERE / "cache", help="downloaded packages and BIOS files")
    ap.add_argument("--v86", type=Path, default=HERE / "node_modules" / "v86", help="the v86 npm package (npm install here)")
    ap.add_argument("--no-www", action="store_true", help="build the rootfs and initramfs only")
    a = ap.parse_args(argv)
    out, cache = a.out.resolve(), a.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    rootfs, kern = out / "rootfs", out / "kernel"
    for d in (rootfs, kern):
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)

    print("1. packages")
    for p in PACKAGES + [KERNEL_PACKAGE]:
        fetch(ALPINE + p + ".apk", cache / (p + ".apk"))
    for name, want in BIOS.items():
        fetch(V86_RAW + name, cache / name)
        got = hashlib.sha256((cache / name).read_bytes()).hexdigest()
        if got != want:
            print(f"  note: {name} differs from the copy fetched on 25 Oct 2026 (sha256 {got[:12]}…)")

    print("2. rootfs")
    for p in PACKAGES:
        unpack_apk(cache / (p + ".apk"), rootfs)
    unpack_apk(cache / (KERNEL_PACKAGE + ".apk"), kern)
    vmlinuz = kern / "boot" / "vmlinuz-virt"
    config = next((kern / "boot").glob("config-*"))
    lsm = [l for l in config.read_text().splitlines() if l.startswith(("CONFIG_LSM=", "CONFIG_SECURITY_LANDLOCK="))]
    print("  kernel:", vmlinuz.name, *lsm)

    print("3. sharness-ai")
    site = next((rootfs / "usr" / "lib").glob("python3.*")) / "site-packages"
    shutil.copytree(REPO / "sharness_ai", site / "sharness_ai",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    wrapper = rootfs / "usr" / "bin" / "sharness-ai"
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -m sharness_ai "$@"\n')
    wrapper.chmod(0o755)
    work = rootfs / "work" / "policies"
    work.mkdir(parents=True)
    for pol in sorted((REPO / "experiments" / "policies").glob("*.json")):
        shutil.copy(pol, work / pol.name)
    init = rootfs / "init"
    shutil.copy(HERE / "init.sh", init)
    init.chmod(0o755)
    for d in ("proc", "sys", "dev", "tmp", "run"):
        (rootfs / d).mkdir(exist_ok=True)

    print("4. initramfs")
    initramfs = out / "initramfs.cpio.gz"
    write_cpio(rootfs, initramfs)
    shutil.copy(vmlinuz, out / "vmlinuz-virt")
    print(f"  {initramfs.name}: {initramfs.stat().st_size / 1e6:.1f} MB; {vmlinuz.name}: {vmlinuz.stat().st_size / 1e6:.1f} MB")

    if not a.no_www:
        print("5. www")
        www = out / "www"
        www.mkdir(exist_ok=True)
        build = a.v86 / "build"
        if not (build / "libv86.mjs").exists():
            sys.exit(f"v86 not found at {a.v86}: run `npm ci` in {HERE} first (package.json pins the version)")
        for src in (build / "libv86.mjs", build / "v86.wasm", cache / "seabios.bin", cache / "vgabios.bin",
                    vmlinuz, initramfs, HERE / "page.html"):
            shutil.copy(src, www / ("index.html" if src.name == "page.html" else src.name))
        print(f"  {www}: {sum(f.stat().st_size for f in www.iterdir()) / 1e6:.1f} MB in {len(list(www.iterdir()))} files")
    print("done:", out)


if __name__ == "__main__":
    main()
