#!/usr/bin/env python3
"""E09: build the Alpine x86 guest that runs sharness-ai under a real Linux kernel in v86.

Standard library only. The result is a kernel and an initramfs that v86 boots in Node and in
a browser tab (boot_node.mjs, boot_browser.mjs), and a rootfs the host kernel can chroot into
(chroot_native.sh). Nothing here is a SHarness component: it is the test bench for E01, E03
and E04 on a second kernel, one that anyone can run without installing anything.

    python3 experiments/browser/build_guest.py [--out DIR] [--cache DIR] [--no-www]

Steps: fetch the pinned Alpine 3.23 x86 packages (busybox, musl, python3 and what they need,
and linux-virt, whose kernel is built with Landlock); unpack them with tarfile; add the virtio-net
driver so the guest has a network card when the page gives it one; add the
sharness_ai package from this checkout and the example policies; write /init (init.sh);
pack a newc cpio, gzipped; copy the kernel, the initramfs, v86 (from node_modules) and the
BIOS files into www/ next to the page, with the playground (playground.html, playground.js),
the example policies and a dev wheel of the package (build_wheel.py) for Pyodide. Re-running only fetches what the cache lacks.
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

# v86 ships its BIOS images in the repository, not in the npm package. Fetched from one commit,
# never from a branch name, so the same bytes come back every time.
V86_COMMIT = "cc37f35c43bf14865d74ad76879ecf9410f69eb1"      # copy/v86 master as of 25 Oct 2026
V86_RAW = f"https://raw.githubusercontent.com/copy/v86/{V86_COMMIT}/bios/"
BIOS = ("seabios.bin", "vgabios.bin")

# Every download is pinned by content. A mismatch stops the build: the guest runs on the
# host kernel in the chroot form, so a tampered package would run as root on the host.
# Recomputed on 25 Oct 2026 with sha256sum over the files fetched that day.
SHA256 = {
    "alpine-baselayout-3.7.2-r0.apk":        "924e13c052c8320a6285b84e81539e510219d3cd03f9346020466f3a9d4d9d19",
    "alpine-baselayout-data-3.7.2-r0.apk":   "f7075b8acf8f10e35fcd1ecd1a4a16a0bf1a9720514ca1579ed1f3a7185cc197",
    "busybox-1.37.0-r30.apk":                "7d79f2a74c32b539be982122c3aa5873bf90bd9a413a2887215f6006d6d546c9",
    "busybox-binsh-1.37.0-r30.apk":          "a2bbfbc28d2981d21afb40961cc2dd2145a02372e1980471a82e090db33b5e39",
    "gdbm-1.26-r0.apk":                      "e4a571f192b4e310b9188efb03afddf1c532eb3a5d4dc2cca2945a77613450b3",
    "libbz2-1.0.8-r6.apk":                   "ecd3e0b59dc6e213cb2f4ca0c1e5262ffbfb2b4c3f49642cb292c407393aba62",
    "libcrypto3-3.5.9-r0.apk":               "2dd6a2737bd3b42a6c17827d742bebbc77747e02c1b8629f0c561511adcd3127",
    "openssl-3.5.9-r0.apk":                  "be17c25ce662f472ead2f38419d8e3ff896a717870b66064d529e2265025a46a",   # sharness-ai session new issues the door's certificates with it
    "libexpat-2.9.0-r0.apk":                 "b8fe248a7ed67e5439467fb2be3b9b0111855fad5251405953207bdb3963b73b",
    "libffi-3.5.2-r0.apk":                   "96aa9d0822f1c743ac5650bd509781cacac92c003a0445c7fdd990a7120a014e",
    "libgcc-15.2.0-r2.apk":                  "ffd1f0472d36b8178499769235f83204421f905515ecf3726f919503254ec259",
    "libncursesw-6.5_p20251123-r0.apk":      "5362c3583de0a4fef106daf08e9e5cebe14a50b27bdb2ac393a0b0b8ba966f7f",
    "libpanelw-6.5_p20251123-r0.apk":        "f5177c0d913d6effd7ae0787b78920263376215aaef69d6b73aeea40d1608b9e",
    "libssl3-3.5.9-r0.apk":                  "d2b16ee4e2c26e21cc2523971d31378c79f3ef5cb2148c5e78fa7e12fc3724be",
    "libstdc++-15.2.0-r2.apk":               "d3dfff6eeadf9d93c1348433c2afed6a3fc895f5516c46bc39b9df00cff31278",
    "linux-virt-6.18.58-r0.apk":             "81ddb2ba30db7b507f51e6ff3fbc74b3e981d8868801a60f113419e3e7e5e32f",
    "mpdecimal-4.0.1-r0.apk":                "839c4c2b77d519795ae3c9940a89a2c33851b04a62f62082b319756916a4e014",
    "musl-1.2.5-r24.apk":                    "cfc373b73542784561f4c16c08e711f720272b0e57325edeb12941b1e77058b4",
    "ncurses-terminfo-base-6.5_p20251123-r0.apk": "55f46b1a5d286eff2579bb77ecd84cabbc61abfa766518490604f867a4ede500",
    "python3-3.12.15-r0.apk":                "f2c947a6c564d4a9aeaed1719502e07b4eb8b3edf5430783930f92dc1597af92",
    "readline-8.3.1-r0.apk":                 "a8f8066105021774a372730aa6092642467dcf4bfa317533fd5c44399dc4f3dd",
    "sqlite-libs-3.53.4-r0.apk":             "e1cec828f9102cbd549b018ad695e57d0e5cfa937f9208096d80d4917768a29a",
    "xz-libs-5.8.4-r0.apk":                  "2febace116cb925a79ace73dd7267a4b571bb1e04e2f61e1763faebf1749c016",
    "zlib-1.3.2-r1.apk":                     "f6a0303e5203a43635d2c8a360a8ef0a6c462d72a123ba96ca82407d5536e2be",
    "seabios.bin":                           "73e3f359102e3a9982c35fce98eb7cd08f18303ac7f1ba6ebfbe6cdc1c244d98",
    "vgabios.bin":                           "a4bc0d80cc3ca028c73dafa8fee396b8d054ce87ebd8abfbd31b06b437607880",
}
APK_META = (".PKGINFO", ".SIGN.", ".post-", ".pre-", ".trigger")


def fetch(url: str, dest: Path):
    """Download once into the cache, then verify. A cached file is verified too, every build."""
    want = SHA256[dest.name]
    if not dest.exists():
        print(f"  fetch {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        if not url.startswith("https://"):
            sys.exit(f"refusing a non-https download: {url}")
        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:  # noqa: S310 - https only, checked above
            shutil.copyfileobj(r, f)
        tmp.rename(dest)
    got = hashlib.sha256(dest.read_bytes()).hexdigest()
    if got != want:
        dest.rename(dest.with_suffix(dest.suffix + ".rejected"))
        sys.exit(f"{dest.name}: sha256 {got} is not the pinned {want}. The file was moved aside, not used. "
                 f"If the upstream changed on purpose, re-pin it in SHA256 with the date.")


def unpack_apk(apk: Path, root: Path):
    """An .apk is concatenated gzip streams of tar: tarfile reads them as one archive."""
    with tarfile.open(apk, "r:gz") as t:
        members = [m for m in t.getmembers()
                   if not m.name.startswith(APK_META) and ".." not in m.name.split("/")
                   and not m.name.startswith("/")]
        for m in members:
            if m.isdev():               # devtmpfs provides device nodes; a cpio of them needs root
                continue
            if (m.issym() or m.islnk()) and ".." in m.linkname.split("/"):
                continue                # a link that climbs out of the tree: never from a package
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
    for name in BIOS:
        fetch(V86_RAW + name, cache / name)

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
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -P -s -m sharness_ai "$@"\n')   # -P -s: never import from the cwd
    wrapper.chmod(0o755)
    work = rootfs / "work" / "policies"
    work.mkdir(parents=True)
    for pol in sorted((REPO / "experiments" / "policies").glob("*.json")):
        shutil.copy(pol, work / pol.name)
    # the network card's driver: virtio-net, a module in Alpine's kernel, with its two dependencies,
    # unpacked so busybox insmod needs no decompressor; v86 presents the card when the page asks for it
    modver = next((kern / "lib" / "modules").iterdir()).name
    moddir = rootfs / "lib" / "modules" / modver
    moddir.mkdir(parents=True, exist_ok=True)
    for rel in ("kernel/net/core/failover.ko.gz", "kernel/drivers/net/net_failover.ko.gz", "kernel/drivers/net/virtio_net.ko.gz"):
        src = kern / "lib" / "modules" / modver / rel
        (moddir / Path(rel).name[:-3]).write_bytes(gzip.decompress(src.read_bytes()))
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
                    vmlinuz, initramfs, HERE / "page.html", HERE / "playground.html", HERE / "playground.js", HERE / "netwatch.js"):
            shutil.copy(src, www / ("index.html" if src.name == "page.html" else src.name))
        (www / "policies").mkdir(exist_ok=True)
        for pol in sorted((REPO / "experiments" / "policies").glob("*.json")):
            shutil.copy(pol, www / "policies" / pol.name)
        for old in www.glob("sharness_ai-*.whl"):
            old.unlink()
        sys.path.insert(0, str(HERE))
        import build_wheel
        print("  wheel:", build_wheel.build(www).name)
        files = [f for f in www.rglob("*") if f.is_file()]
        print(f"  {www}: {sum(f.stat().st_size for f in files) / 1e6:.1f} MB in {len(files)} files")
    print("done:", out)


if __name__ == "__main__":
    main()
