"""Where the output goes, and what it can show.

A terminal gets colour and box-drawing characters; a pipe, a file, `NO_COLOR`, `TERM=dumb`,
`--plain` or `SHARNESS_AI_PLAIN=1` get plain ASCII, so the same screen survives a serial
console (the Linux guest in the browser tab) and a log file. Detection is in one place so
that no screen decides for itself.
"""
import os
import shutil
import sys
from dataclasses import dataclass

STYLES = {"ok": "32", "no": "31", "warn": "33", "todo": "33", "dim": "2", "bold": "1",
          "head": "36", "accent": "35", "ask": "35"}
UNICODE = {"ok": "✔", "no": "✘", "todo": "○", "ask": "?", "dot": "·", "ellipsis": "…",
           "bar": "█", "pad": "░", "arrow": "→", "mark": "»",
           "tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│", "lt": "├", "rt": "┤",
           "tt": "┬", "bt": "┴"}
ASCII = {"ok": "[ok]", "no": "[no]", "todo": "[  ]", "ask": "[??]", "dot": "-", "ellipsis": "...",
         "bar": "#", "pad": ".", "arrow": "->", "mark": ">>",
         "tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lt": "+", "rt": "+",
         "tt": "+", "bt": "+"}
MIN_WIDTH, MAX_WIDTH, DEFAULT_WIDTH = 40, 200, 80


def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


@dataclass
class Term:
    width       : int  = DEFAULT_WIDTH
    color       : bool = False
    unicode     : bool = False
    interactive : bool = False
    err         : bool = False          # write to stderr instead of stdout (run's own lines)

    @classmethod
    def detect(cls, plain: bool = False, width: int = None, err: bool = False) -> "Term":
        """Read the environment once. `plain` forces ASCII and no colour; `width` overrides."""
        out = sys.stderr if err else sys.stdout
        tty = _isatty(out)
        term_var = os.environ.get("TERM", "")
        plain = plain or bool(os.environ.get("SHARNESS_AI_PLAIN")) or term_var == "dumb"
        color = tty and not plain and "NO_COLOR" not in os.environ and bool(term_var)
        encoding = (getattr(out, "encoding", None) or "").lower()
        unicode = not plain and "utf" in encoding
        interactive = tty and _isatty(sys.stdin) and sys.platform != "emscripten"
        if width is None:
            try:
                width = int(os.environ.get("COLUMNS", "")) if os.environ.get("COLUMNS") else None
            except ValueError:
                width = None
        if width is None:
            width = shutil.get_terminal_size((DEFAULT_WIDTH, 24)).columns if tty else DEFAULT_WIDTH
        return cls(width=max(MIN_WIDTH, min(MAX_WIDTH, width)), color=color, unicode=unicode,
                   interactive=interactive, err=err)

    @classmethod
    def plain(cls, width: int = DEFAULT_WIDTH, interactive: bool = False) -> "Term":
        """ASCII, no colour, fixed width: what the tests draw with."""
        return cls(width=width, color=False, unicode=False, interactive=interactive)

    @property
    def stream(self):
        return sys.stderr if self.err else sys.stdout

    def glyph(self, name: str) -> str:
        return (UNICODE if self.unicode else ASCII)[name]

    def style(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(STYLES[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"

    def mark(self, name: str) -> str:
        """A verdict mark in its colour: ok, no, todo, ask."""
        return self.style(self.glyph(name), name)

    def shorten(self, text: str, width: int) -> str:
        """Cut the middle out of a long value (a hash, a path list) so a row stays one line."""
        if len(text) <= width:
            return text
        e = self.glyph("ellipsis")
        keep = max(1, width - len(e))
        head = (keep + 1) // 2
        return text[:head] + e + text[len(text) - (keep - head):]

    def write(self, *lines: str):
        for line in lines:
            print(line, file=self.stream)
        self.stream.flush()
