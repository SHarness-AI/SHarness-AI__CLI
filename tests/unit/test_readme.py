"""The README is the PyPI page: every image and link in it must resolve there, where there is no
repository to resolve a relative path against (the broken figure on v0.2.0's page, 29 Oct 2026)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Test_Readme_On_PyPI:
    def test_no_relative_image_or_link(self):
        text = (ROOT / "README.md").read_text()
        targets = re.findall(r"\]\(([^)\s]+)", text) + re.findall(r'src="([^"]+)"', text)
        relative = [t for t in targets if not t.startswith(("https://", "http://", "#", "mailto:"))]
        assert relative == [], f"relative in README.md, broken on PyPI: {relative}"

    def test_every_absolute_repository_path_exists_here(self):
        text = (ROOT / "README.md").read_text()
        paths = re.findall(r"SHarness-AI/SHarness-AI__CLI/(?:blob/)?main/([^)\s\"#]+)", text)
        missing = [p for p in paths if not (ROOT / p).exists()]
        assert paths and missing == [], f"README points at files that are not in the tree: {missing}"
