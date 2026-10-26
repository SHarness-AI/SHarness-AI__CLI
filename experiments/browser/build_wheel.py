#!/usr/bin/env python3
"""Build a wheel of sharness_ai from this checkout, standard library only, for the browser.

The playground installs it into Pyodide with micropip, the way a reader would `pip install`.
PyPI carries only the released version; this wheel is the `dev` branch as it stands, so its
version says so: <pyproject version>+dev.<commit>, a PEP 440 local version, never uploaded.

    python3 experiments/browser/build_wheel.py [--out DIR]

Next to the wheel it writes wheel.json (name, version, size, sha256, date), which the
playground reads to know what to install.
"""
import argparse
import base64
import hashlib
import re
import subprocess
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def version() -> str:
    base = re.search(r'^version\s*=\s*"v?([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M).group(1)
    try:
        sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short=7", "HEAD"],  # noqa: S603,S607 - git from PATH, fixed argv
                             capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sha = "local"
    return f"{base}+dev.{sha}"


def build(out: Path, ver: str = None, src: Path = None) -> Path:
    """`ver` names the wheel (default: <pyproject version>+dev.<commit>); `src` is the package
    directory to pack (default: this checkout's sharness_ai)."""
    ver = ver or version()
    src = src or REPO / "sharness_ai"
    dist = f"sharness_ai-{ver}.dist-info"
    files = {}
    for f in sorted(src.rglob("*")):                       # the package and its subpackages (cli/, ui/)
        if f.is_file() and f.suffix in (".py", "") and "__pycache__" not in f.parts:
            files[f"sharness_ai/{f.relative_to(src).as_posix()}"] = f.read_bytes()
    files["sharness_ai/version"] = f"v{ver}\n".encode()
    files[f"{dist}/METADATA"] = (
        "Metadata-Version: 2.1\nName: sharness-ai\nVersion: " + ver + "\n"
        "Summary: SHarness CLI, experiments stage (dev build for the browser playground)\n"
        "Home-page: https://sharness.ai\nLicense: Apache-2.0\nRequires-Python: >=3.11\n").encode()
    files[f"{dist}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: sharness-ai build_wheel.py\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[f"{dist}/entry_points.txt"] = b"[console_scripts]\nsharness-ai=sharness_ai.cli:main\n"
    record = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append(f"{name},sha256={digest},{len(data)}")
    record.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()
    out.mkdir(parents=True, exist_ok=True)
    whl = out / f"sharness_ai-{ver}-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
    data = whl.read_bytes()
    import datetime
    import json
    (out / "wheel.json").write_text(json.dumps({
        "wheel": whl.name, "version": ver, "size": len(data),
        "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
        "built": datetime.date.today().isoformat()}, indent=1) + "\n")
    return whl


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=HERE / "out" / "www")
    ap.add_argument("--version", help="name the wheel this version instead of <pyproject>+dev.<commit>")
    a = ap.parse_args(argv)
    whl = build(a.out, a.version)
    print(f"{whl}  {whl.stat().st_size} bytes")


if __name__ == "__main__":
    main()
