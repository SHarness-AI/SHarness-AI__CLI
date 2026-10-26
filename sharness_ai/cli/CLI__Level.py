"""One verb per level: `contain` (5), `profile` (4), `explain` (any document, drawn down the
grid). Level 3 is `policy`, which learns to read a levelled document; levels 1 and 0 are
`translate`, `run --verbose`, `hello` and `doctor`, which exist. Every screen prints the hash of
what the person wrote and the next command one level down."""
import json
import os

from sharness_ai.level import Chain, level_of
from sharness_ai.level.l4.L4 import L4
from sharness_ai.level.l5.L5 import DEFAULT_PROFILE
from sharness_ai.policy import PolicyError, load

EXIT_ERROR = 2


class CLI__Level:
    def __init__(self, main):
        self.main = main

    # ---- shared drawing -----------------------------------------------------------------------
    def _report_lines(self, chain: Chain) -> list:
        d, t = self.main.draw, self.main.term
        r = chain.report()
        lines = d.kv("held", f"{t.mark('ok')} {r['held']} rows by the kernel: files, ports, caps; nothing else is reachable", style="ok")
        for i, u in enumerate(r["unheld"]):
            lines += d.kv("not held" if i == 0 else "", f"{t.glyph('ask') if not t.unicode else '⚠'} {u}", style="warn" if i == 0 else None)
        for i, u in enumerate(r["passthrough"]):
            lines += d.kv("passed through" if i == 0 else "", u, style="accent" if i == 0 else None)
        lines += d.kv("not covered", " · ".join(r["not_covered"]) if t.unicode else " - ".join(r["not_covered"]), style="dim")
        return lines

    def _became(self, chain: Chain) -> str:
        parts = []
        for s in chain.steps:
            if s.level == 4:
                parts.append(f"profile {s.document['profile']} (4)")
            elif s.level == 3:
                v = s.document
                n = sum(len(v.get("files", {}).get(k, [])) for k in ("read", "write", "exec"))
                parts.append(f"{n} path rows + network + caps (3)")
            elif s.level == 2:
                parts.append("one door, the kernel (2)")
            elif s.level == 1:
                m = s.document
                parts.append(f"{sum(m['landlock_paths'].values()) + len(m['landlock_tcp_ports'])} kernel rules (1)")
        return f" {self.main.term.glyph('arrow')} ".join(parts)

    def _load_chain(self, path: str):
        try:
            doc = load(path)
            return Chain.from_document(doc, ground=self.main.state.get("hello") or None)
        except FileNotFoundError:
            self.main.fail(f"no such file: {path}", hint="sharness-ai contain … --save FILE writes one; sharness-ai policy new FILE too", code=EXIT_ERROR)
        except PolicyError as e:
            self.main.fail(str(e), hint="sharness-ai policy check FILE says what is wrong, at the level the file is written", code=EXIT_ERROR)
        return None

    # ---- level 5: contain -------------------------------------------------------------------------
    def cmd_contain(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        ws = os.path.realpath(args.workspace)
        agent = args.agent or (os.path.basename(args.argv[1] if args.argv[:1] == ["--"] and len(args.argv) > 1 else (args.argv[0] if args.argv else "agent")))
        contain = {"agent": agent, "workspace": ws, "sites": args.sites or [], "secrets": args.secrets or [],
                   "profile": args.profile}
        budget = {}
        if args.memory_mb is not None:
            budget["memory_mb"] = args.memory_mb
        if args.pids is not None:
            budget["pids"] = args.pids
        if budget:
            contain["budget"] = budget
        doc = {"pbp": 1, "level": 5, "contain": contain}
        try:
            chain = Chain.from_document(doc, ground=m.state.get("hello") or None)
        except PolicyError as e:
            return m.fail(str(e), hint="sharness-ai profile list shows the profiles; sites are host names", code=EXIT_ERROR)
        top = chain.top
        if args.expect_hash and args.expect_hash != top.hash:
            print(f"sharness-ai contain: refused. The sentence hashes to {top.hash}; the hash supplied was "
                  f"{args.expect_hash}. Nothing ran.", file=t.stream)
            return 125
        if m.json:
            print(json.dumps({"document": doc, "hashes": chain.report()["hashes"], "v0": chain.v0, "report": chain.report()}, indent=1))
        else:
            lines = d.head("contain", "one sentence, compiled to the kernel, named by one hash")
            lines += d.kv("you said", top.notes[0], style="bold")
            lines += d.kv("it became", self._became(chain))
            lines += d.kv("the name", f"{top.hash}   every level below is recomputed from it", style="accent")
            lines += self._report_lines(chain)
            lines += d.kv("deeper", "sharness-ai explain FILE   the same sentence drawn level by level (--save FILE keeps it)", style="head")
            t.write(*lines)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=1)
                f.write("\n")
            m.state.record("policy", file=os.path.abspath(args.save), id=agent, hash=top.hash, level=5)
            if not m.json:
                t.write(*d.kv("saved", f"{args.save}   the level-5 document; sharness-ai explain {args.save}", style="ok"))
        argv = args.argv[1:] if args.argv[:1] == ["--"] else list(args.argv)
        if not argv or args.dry_run:
            return 0
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="sharness-ai-contain-", delete=False) as f:
            json.dump(chain.v0, f)
            v0_path = f.name
        try:
            ns = type("A", (), {})()
            ns.policy, ns.expect_hash, ns.verbose, ns.quiet, ns.best_effort, ns.argv = v0_path, chain.at(2).hash, False, False, False, argv
            ns.next_hint = (f"sharness-ai explain {args.save}   the sentence drawn level by level" if args.save else
                            "sharness-ai contain … --save FILE keeps the sentence; sharness-ai explain FILE draws it level by level")
            return m.runner.cmd_run(ns)
        finally:
            try:
                os.unlink(v0_path)
            except OSError:
                pass

    # ---- level 4: profile -----------------------------------------------------------------------------
    def cmd_profile(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        if args.profile_cmd in (None, "list"):
            if m.json:
                print(json.dumps({n: {"title": L4.load(n).get("title"), "blanks": L4.load(n).get("blanks")} for n in L4.names()}, indent=1))
                return 0
            lines = d.head("profile", "the vendor's level: a role, and the blanks a person fills")
            for n in L4.names():
                p = L4.load(n)
                lines += d.kv(n, p.get("title", ""))
            lines += d.kv("blanks", "workspace (always yours), sites, secrets, memory_mb, pids; a profile's defaults show with profile show NAME", style="dim")
            lines += d.kv("next", f"sharness-ai contain --profile {DEFAULT_PROFILE} --workspace . --sites github.com -- CMD", style="head")
            t.write(*lines)
            return 0
        try:
            p = L4.load(args.name)
        except PolicyError as e:
            return m.fail(str(e), code=EXIT_ERROR)
        if args.profile_cmd == "show":
            if m.json:
                print(json.dumps(p, indent=1))
                return 0
            lines = d.head("profile", f"{args.name}: {p.get('title', '')}")
            lines += d.kv("version", str(p.get("version", 1)))
            lines += d.kv("blanks", ", ".join(f"{k}={'(yours)' if v is None else v}" for k, v in p["blanks"].items()))
            lines += d.kv("notes", p.get("notes", ""))
            lines += d.kv("template", "the level-3 rows with $blanks:", style="bold")
            for line in json.dumps(p["template"], indent=1).splitlines():
                lines.append("    " + line)
            lines += d.kv("next", f"sharness-ai contain --profile {args.name} --workspace . -- CMD", style="head")
            t.write(*lines)
            return 0
        return m.fail(f"profile {args.profile_cmd}: not a command", code=EXIT_ERROR)

    # ---- explain: the column of the grid -------------------------------------------------------------
    def cmd_explain(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        chain = self._load_chain(args.file)
        if chain is None:
            return EXIT_ERROR
        if m.json:
            print(json.dumps({"steps": [{"level": s.level, "name": s.name, "hash": s.hash, "notes": s.notes, "unheld": s.unheld,
                                         "passthrough": s.passthrough, "document": s.document} for s in chain.steps]}, indent=1))
            return 0
        lines = d.head("explain", "one document, every level below it, hash by hash")
        lines.append("")
        label_of = {5: "what you wrote", 4: "the vendor's", 3: "what a manager reads", 2: "the architecture", 1: "what the kernel is told", 0: "measured"}
        for s in chain.steps:
            body = list(s.notes)
            if s.level == 3:
                v = s.document
                body = [f"read {d.paths(v['files'].get('read', []), 40)} · write {d.paths(v['files'].get('write', []), 30)}",
                        f"exec {d.paths(v['files'].get('exec', []), 40)}",
                        "network " + ("none" if v.get("network") == "none" else " ".join(v["network"].get("sites", [])) or str(v["network"]))
                        + f" · memory {v.get('process', {}).get('max_memory_mb', 'no cap')} MiB · pids {v.get('process', {}).get('max_pids', 'no cap')}"]
                body += [f"{t.glyph('mark')} {p}" for p in s.passthrough]
            if s.level == 2:
                v = s.document
                net = v.get("network")
                body = ["sharness.kernel (live): the only door in v0 " + t.glyph("dot") + " ports " + ("none" if net == "none" else " ".join(map(str, net["connect_tcp_ports"])))]
                body += [f"unheld: {u.split(':')[0]}" for u in chain.at(3).unheld] if any(x.level == 3 for x in chain.steps) else []
            if s.level == 0:
                body = s.notes
            box = d.box(f"{s.level} {s.name}", body or [""])
            tag = (f"{s.hash}  " if s.hash else "") + label_of[s.level]
            lines.append(f"  {box[0]}")
            lines += [f"  {x}" for x in box[1:-1]]
            if len(box[-1]) + len(tag) + 4 <= t.width:
                lines.append(f"  {box[-1]}  {t.style(tag, 'dim')}")
            else:
                lines.append(f"  {box[-1]}")
                lines.append(f"    {t.style(tag, 'dim')}")
            if s.level > 1 and s is not chain.steps[-1]:
                lines.append(f"  {' ' * (len(box[0]) // 2)}{t.glyph('v')}")
        lines.append("")
        lines += self._report_lines(chain)
        lv = level_of(load(args.file))
        nxt = (f"sharness-ai policy show {args.file}   the level-3 rows in full" if lv > 3 else
               f"sharness-ai run --policy {args.file} --expect-hash {chain.top.hash} -- CMD")
        lines += d.kv("next", nxt, style="head")
        t.write(*lines)
        return 0
