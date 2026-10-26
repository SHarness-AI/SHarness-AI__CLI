"""Questions with a default, and a path that never blocks: on a pipe, in Pyodide or in a test
the answer is the default or the next item of `answers`, so every screen that asks can also
be scripted. A question shows its default before accepting it: nobody gets a grant they did
not make."""
import os
import select
import sys

from sharness_ai.ui.Term import Term

DEFAULT_TIMEOUT = 120                            # seconds; SHARNESS_AI_PROMPT_TIMEOUT overrides


class Prompt:
    def __init__(self, term: Term, answers: list = None, timeout: float = None):
        self.t = term
        self.answers = list(answers or [])
        self.asked = []                          # (question, answer), for tests and --debug
        env = os.environ.get("SHARNESS_AI_PROMPT_TIMEOUT")
        self.timeout = timeout if timeout is not None else float(env) if env else DEFAULT_TIMEOUT

    def _input(self, text: str):
        """input() with a timeout: a terminal nobody is typing at (an agent's tty) gets the
        default after `timeout` seconds instead of hanging the session. sgit's CLI__Input."""
        print(text, end="", flush=True, file=self.t.stream)
        try:
            ready, _, _ = select.select([sys.stdin], [], [], self.timeout)
        except (OSError, ValueError):            # no select on this stdin (Windows): plain input
            return input()
        if not ready:
            self.t.write(f"  (no answer in {int(self.timeout)} s: the default)")
            return None
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\n")

    def _read(self, text: str):
        """The raw answer, or None when nobody can answer."""
        if self.answers:
            a = self.answers.pop(0)
            self.t.write(text + (a or ""))
            return a
        if not self.t.interactive:
            return None
        try:
            return self._input(text)
        except EOFError:
            self.t.write("")
            return None

    def ask(self, question: str, default: str = "", hint: str = "", prefix: str = "") -> str:
        shown = f"  {prefix}" if not question else f"  {prefix}{question:<34} "
        if default:
            shown += self.t.style(f"[{default}]", "dim") + "  "
        if hint:
            shown += self.t.style(hint, "dim") + "  "
        raw = self._read(shown)
        answer = default if raw is None or raw.strip() == "" else raw.strip()
        self.asked.append((question, answer))
        return answer

    def choose(self, question: str, options: list, default: str = None) -> str:
        """options: (key, label). Returns the key; an unknown answer re-asks while interactive."""
        keys = [k for k, _ in options]
        while True:
            self.t.write("  " + question)
            for k, label in options:
                self.t.write(f"    {self.t.style(k, 'bold')}  {label}")
            raw = self._read(f"  {self.t.glyph('arrow')} ")
            if raw is None or raw.strip() == "":
                answer = default if default is not None else keys[0]
            else:
                answer = raw.strip()
            if answer in keys:
                self.asked.append((question, answer))
                return answer
            self.t.write(f"  {self.t.mark('no')} {answer!r} is not one of {', '.join(keys)}")
            if not self.t.interactive and not self.answers:
                return default if default is not None else keys[0]

    def confirm(self, question: str, default: bool = True) -> bool:
        raw = self._read(f"  {question} {self.t.style('[Y/n]' if default else '[y/N]', 'dim')} ")
        if raw is None or raw.strip() == "":
            return default
        return raw.strip().lower() in ("y", "yes")
