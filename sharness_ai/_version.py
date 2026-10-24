"""VERSION — resolved from the `version` file the release pipeline maintains
(.github/workflows/workflow.yml bumps it, together with pyproject.toml, on every main release)."""
import os

VERSION_FILE     = os.path.join(os.path.dirname(__file__), 'version')
FALLBACK_VERSION = 'v0.0.0-dev'


def _resolve_version() -> str:
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip() or FALLBACK_VERSION
    except OSError:
        return FALLBACK_VERSION


VERSION = _resolve_version()
