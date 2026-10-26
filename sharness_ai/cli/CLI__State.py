"""What this machine has done with sharness-ai, for the guide's ladder: the last probe, the
last hello result, the last policy written, the last run. One small JSON file under
$SHARNESS_AI_STATE, else $XDG_STATE_HOME/sharness-ai/state.json, else ~/.local/state/…
Never required: where it cannot be written (Pyodide, a read-only home) the ladder shows
only what this session did. Nothing here leaves the machine."""
import json
import os
import time


class CLI__State:
    def __init__(self, path: str = None):
        self.path = path or self._default_path()
        self.data = self._load()

    @staticmethod
    def _default_path() -> str:
        env = os.environ.get("SHARNESS_AI_STATE")
        if env:
            return env
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        return os.path.join(base, "sharness-ai", "state.json")

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1)
            os.replace(tmp, self.path)
            return True
        except OSError:
            return False

    def record(self, key: str, **fields) -> dict:
        entry = dict(fields, at=time.strftime("%Y-%m-%d %H:%M", time.gmtime()))
        self.data[key] = entry
        self.save()
        return entry

    def get(self, key: str) -> dict:
        v = self.data.get(key)
        return v if isinstance(v, dict) else {}
