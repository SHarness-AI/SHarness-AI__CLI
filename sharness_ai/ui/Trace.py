"""The --debug trace: each step of a command with its duration, printed at the end, the way
sgit's debug log prints its network calls. Off, it costs a dictionary lookup per step."""
import time
from contextlib import contextmanager

from sharness_ai.ui.Term import Term


class Trace:
    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self.steps = []                  # (name, seconds, note)
        self.started = time.monotonic()

    @contextmanager
    def step(self, name: str):
        t0 = time.monotonic()
        try:
            yield
        finally:
            if self.enabled:
                self.steps.append((name, time.monotonic() - t0, ""))

    def note(self, text: str):
        if self.enabled:
            self.steps.append(("note", 0.0, text))

    def render(self, term: Term) -> list:
        if not self.enabled:
            return []
        out = [term.style("debug", "bold") + "   steps and their timings:"]
        for name, secs, note in self.steps:
            if name == "note":
                out.append(f"          {term.style(note, 'dim')}")
            else:
                out.append(f"  {secs * 1000:8.1f} ms  {name}")
        out.append(f"  {(time.monotonic() - self.started) * 1000:8.1f} ms  total")
        return out
