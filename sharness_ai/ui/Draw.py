"""The drawings: the banner, label/value rows, verdict rows, boxes side by side, the policy as
one process with its edges, bars, rules and the ladder. Every method returns lines for the Term
it was given, so the same screen is drawn in box characters on a terminal and in ASCII on a pipe.
"""
import textwrap

from sharness_ai.ui.Term import Term

BANNER = (
    r"   ____  _   _                                ",
    r"  / ___|| | | | __ _ _ __ _ __   ___  ___ ___ ",
    r"  \___ \| |_| |/ _` | '__| '_ \ / _ \/ __/ __|",
    r"   ___) |  _  | (_| | |  | | | |  __/\__ \__ \ ",
    r"  |____/|_| |_|\__,_|_|  |_| |_|\___||___/___/",
)
SITE    = "https://sharness.ai"
CAVEAT  = ("applied by a process to its own child: a Boundary for the child, a Setting for the parent, "
           "who could have skipped it. The launcher that binds the agent too is the design, not code.")
LABEL_W = 16


class Draw:
    def __init__(self, term: Term):
        self.t = term

    # ---- text -------------------------------------------------------------------------------
    def kv(self, label: str, text: str, label_w: int = LABEL_W, indent: int = 2, style: str = None,
           wrap: bool = True) -> list:
        """`  label           text, wrapped to the width and indented under itself`. A command the
        person will copy is not wrapped (wrap=False): it overflows rather than breaks."""
        width = max(20, self.t.width - indent - label_w)
        lines = (textwrap.wrap(text, width, break_on_hyphens=False, break_long_words=False) if wrap else [text]) or [""]
        shown = label.ljust(label_w) if len(label) < label_w else label + " "
        head = " " * indent + (self.t.style(shown, style) if style else shown)
        pad = " " * (indent + len(shown))
        return [head + lines[0]] + [pad + x for x in lines[1:]]

    def head(self, command: str, text: str) -> list:
        return [self.t.style(f"sharness-ai {command}", "bold") + "   " + self.t.style(text, "dim")]

    def rule(self, text: str = "") -> str:
        h = self.t.glyph("h")
        if not text:
            return h * self.t.width
        body = f"{h * 2} {text} "
        return body + h * max(0, self.t.width - len(body))

    def hash_short(self, h: str) -> str:
        """sha256:3b8a…e1c0: enough to recognise, never enough to check (the full hash is printed once)."""
        return h if len(h) <= 19 else h[:11] + self.t.glyph("ellipsis") + h[-4:]

    def paths(self, items: list, width: int) -> str:
        """The first paths that fit, then `+N`: a list is never cut inside a path."""
        if not items:
            return "none"
        shown, used = [], 0
        for i, p in enumerate(items):
            more = len(items) - i
            tail = f" +{more}" if more else ""
            if shown and used + 1 + len(p) + len(tail) > width:
                return " ".join(shown) + f" +{len(items) - len(shown)}"
            if not shown and len(p) > width:
                return self.t.shorten(p, width - (len(tail) if more > 1 else 0)) + (f" +{more - 1}" if more > 1 else "")
            shown.append(p)
            used += len(p) + (1 if len(shown) > 1 else 0)
        return " ".join(shown)

    # ---- verdicts ---------------------------------------------------------------------------
    def row(self, verdict: str, what: str, target: str, result: str, note: str = "") -> str:
        """`  ✔ read      /etc/hostname           allowed`, plus a dim note after it. `verdict`
        is ok, no, ask (inconclusive) or todo."""
        mark = self.t.mark(verdict)
        tgt = self.t.shorten(target, 28)
        line = f"  {mark} {what:<9} {tgt:<28} {result}"
        if note:
            line += "  " + self.t.style(note, "dim")
        return line

    def bar(self, n: int, of: int, width: int = 12) -> str:
        of = max(of, 1)
        filled = round(width * min(n, of) / of)
        return self.t.glyph("bar") * filled + self.t.glyph("pad") * (width - filled)

    def ladder(self, steps: list) -> list:
        """steps: (done, number, name, text). done is True, False or None (unknown)."""
        out = []
        for done, n, name, text in steps:
            mark = self.t.mark("ok" if done else "todo") if done is not None else self.t.mark("ask")
            out.append(f"{mark} {n}  {name:<10} {text}")
        return out

    # ---- boxes ------------------------------------------------------------------------------
    def box(self, title: str, lines: list, width: int = None) -> list:
        g = self.t.glyph
        inner = max([len(x) for x in lines] + [len(title) + 3])
        if width:
            inner = max(inner, width - 4)
        top = f"{g('tl')}{g('h')} {title} " + g("h") * (inner - len(title) - 1) + g("tr")
        body = [f"{g('v')} {x:<{inner}} {g('v')}" for x in lines]
        bottom = g("bl") + g("h") * (inner + 2) + g("br")
        return [top] + body + [bottom]

    def beside(self, blocks: list, indent: int = 2, gap: int = 2) -> list:
        """Blocks side by side when they fit in the width, stacked when they do not."""
        widths = [max(len(x) for x in b) for b in blocks]
        if sum(widths) + gap * (len(blocks) - 1) + indent <= self.t.width:
            height = max(len(b) for b in blocks)
            rows = []
            for i in range(height):
                cells = [(b[i] if i < len(b) else "").ljust(w) for b, w in zip(blocks, widths)]
                rows.append(" " * indent + (" " * gap).join(cells).rstrip())
            return rows
        out = []
        for b in blocks:
            out += [" " * indent + x for x in b]
        return out

    # ---- the policy as one process with its edges --------------------------------------------
    def policy(self, policy: dict, h: str = None, problems: list = ()) -> list:
        """The drawing every screen shares: files, network, process; the hash; the caveat."""
        files = policy.get("files") if isinstance(policy.get("files"), dict) else {}
        net = policy.get("network")
        proc = policy.get("process") if isinstance(policy.get("process"), dict) else {}
        w = 26 if self.t.width >= 100 else 22
        fbox = self.box("files", [f"read  {self.paths(files.get('read', []), w)}",
                                  f"write {self.paths(files.get('write', []), w)}",
                                  f"exec  {self.paths(files.get('exec', []), w)}"])
        if net == "none":
            nlines = ["connect_tcp  none", "UDP and Unix sockets", "are not covered"]
        elif isinstance(net, dict):
            ports = net.get("connect_tcp_ports", [])
            nlines = [f"connect_tcp  {self.t.shorten(' '.join(map(str, ports)) or 'none', 14)}",
                      "any host on those ports;", "UDP is not covered"]
        else:
            nlines = ["network: not set", "", ""]
        nbox = self.box("network", nlines)
        mem = proc.get("max_memory_mb")
        pids = proc.get("max_pids")
        plines = [f"memory  {str(mem) + ' MiB' if mem is not None else 'no cap'}",
                  f"pids    {pids if pids is not None else 'no cap'}",
                  f"no_new_privs {'yes' if proc.get('no_new_privs', True) is True else 'NO'}"]
        pbox = self.box("process", plines)
        out = self.beside([fbox, nbox, pbox])
        if h:
            out.append("  " + self.t.style(h, "accent") + "  " + self.t.style("its name: change a row and it changes", "dim"))
        for p in problems:
            out.append(f"  {self.t.mark('no')} {p}")
        return out

    def caveat(self) -> list:
        return self.kv("caveat", CAVEAT, style="dim")

    # ---- the banner -------------------------------------------------------------------------
    def banner(self, version: str, status: str = "status: experiments") -> list:
        if self.t.width < 72:
            return [self.t.style("SHarness", "bold") + f"  sharness-ai {version}  {self.t.style(status, 'dim')}  {SITE}"]
        side = ["", "", f"sharness-ai {version}", status, SITE]
        return [self.t.style(a, "head") + "      " + self.t.style(b, "dim") for a, b in zip(BANNER, side)]

    def menu(self, items: list) -> str:
        """items: (key, label). One line when it fits, otherwise wrapped."""
        parts = [f"{self.t.style(k, 'bold')} {label}" for k, label in items]
        return "   ".join(parts)
