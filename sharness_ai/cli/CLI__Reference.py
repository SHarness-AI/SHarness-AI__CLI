"""`sharness-ai help [--format text|json]`: the command surface, read from the live argparse tree.

Hand-written command tables drift: a flag is added or renamed and the README, the site's CLI
page and the skill keep describing the old one. This walks the parser CLI__Main builds, so the
output is the code: it cannot name a command that does not exist or miss one that does. The
JSON form is what the website agent reads to write code/cli/index.md, and what two releases
are diffed by. The lesson is sgit's CLI__Reference."""
import argparse
import json

from sharness_ai._version import VERSION

SCHEMA = "sharness-ai.cli-reference/v0"


class CLI__Reference:
    def __init__(self, main):
        self.main = main

    @staticmethod
    def _sub(parser):
        for a in parser._actions:
            if isinstance(a, argparse._SubParsersAction):
                return a
        return None

    @staticmethod
    def _options(parser) -> list:
        out = []
        for a in parser._actions:
            if isinstance(a, argparse._SubParsersAction) or not a.option_strings or "--help" in a.option_strings:
                continue
            out.append({"flags": list(a.option_strings), "help": (a.help or "").strip(),
                        "choices": [str(c) for c in a.choices] if a.choices else []})
        return out

    @staticmethod
    def _positionals(parser) -> list:
        return [{"name": a.dest, "help": (a.help or "").strip(), "required": a.nargs not in ("?", "*", argparse.REMAINDER)}
                for a in parser._actions
                if not isinstance(a, argparse._SubParsersAction) and not a.option_strings]

    def walk(self, parser, path="sharness-ai") -> dict:
        sub = self._sub(parser)
        node = {"path": path, "help": (parser.description or "").strip(), "options": self._options(parser),
                "positionals": self._positionals(parser), "commands": []}
        if sub:
            helps = {a.dest: (a.help or "").strip() for a in sub._choices_actions}
            seen = set()
            for name, p in sub.choices.items():
                if id(p) in seen:
                    continue
                seen.add(id(p))
                child = self.walk(p, f"{path} {name}")
                child["help"] = helps.get(name, "") or child["help"]
                node["commands"].append(child)
        return node

    def reference(self) -> dict:
        tree = self.walk(self.main.build_parser())
        return {"schema": SCHEMA, "version": VERSION, "tree": tree}

    def text(self, node: dict, depth: int = 0) -> list:
        t = self.main.term
        out = []
        if depth:
            flags = " ".join(o["flags"][0] for o in node["options"])
            pos = " ".join(p["name"].upper() for p in node["positionals"])
            head = f"{'  ' * depth}{t.style(node['path'], 'bold')} {pos} {t.style(flags, 'dim')}".rstrip()
            out.append(head)
            if node["help"]:
                out.append(f"{'  ' * depth}    {node['help']}")
        for c in node["commands"]:
            out += self.text(c, depth + 1)
        return out

    def cmd_help(self, args) -> int:
        ref = self.reference()
        if args.format == "json" or self.main.json:
            print(json.dumps(ref, indent=1))
            return 0
        d = self.main.draw
        lines = d.head("help", f"every command, read from the parser itself (sharness-ai {VERSION})")
        lines += self.text(ref["tree"])
        lines.append("")
        lines += d.kv("as json", "sharness-ai help --format json: the same tree for a page or a diff", style="dim")
        self.main.term.write(*lines)
        return 0
