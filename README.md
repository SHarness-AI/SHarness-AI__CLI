# sharness-ai — the SHarness-AI CLI

[![PyPI](https://img.shields.io/pypi/v/sharness-ai)](https://pypi.org/project/sharness-ai/)
[![Python](https://img.shields.io/pypi/pyversions/sharness-ai)](https://pypi.org/project/sharness-ai/)
![Current Release](https://img.shields.io/badge/release-v0.0.0-blue)

## Install

```bash
pip install sharness-ai
```

This gives you two CLI commands: `sharness-ai` and the shorthand `sharness`.

```bash
sharness --version
```

## Releases

Every push to `main` runs `.github/workflows/workflow.yml`: unit tests, then a version bump
(`v0.N.0` → `v0.N+1.0`, written to `pyproject.toml`, `sharness_ai/version` and the badge above),
a git tag, and a publish to PyPI via Trusted Publishing (OIDC — no API token is stored).
