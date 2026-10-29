"""`sharness-ai policy`: hash, check, show, translate, new (the wizard) and edit (one edge).

Every screen draws the policy the same way (Draw.policy) and ends with the next command. The
wizard's defaults encode what the experiments taught: the ELF interpreter needs the execute
right, so exec always carries the library directories; read carries the current directory
because that is where the tool's files are; write is nowhere until said."""
import json
import os
import sys

from sharness_ai.policy import PolicyError, advice, check, load, policy_hash, summary

SYSTEM     = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc")
EDGES      = ("read", "write", "exec", "ports", "memory", "pids")
QUESTIONS  = {"read":   "what may it read?",
              "write":  "where may it write?",
              "exec":   "what may it run?",
              "ports":  "which TCP ports may it connect to?",
              "memory": "memory cap, in MiB?",
              "pids":   "how many processes at most?"}
EXIT_PROBLEMS = 1
EXIT_ERROR    = 2


def _list(text: str) -> list:
    text = text.strip()
    if text.lower() in ("", "none", "nowhere", "nothing", "-"):
        return []
    return [x for x in text.replace(",", " ").split() if x]


def _existing(paths) -> list:
    return [p for p in paths if os.path.isdir(p)]


class CLI__Policy:
    def __init__(self, main):
        self.main = main

    # ---- loading, with the sentence and the hint ----------------------------------------------
    def _load(self, path: str):
        try:
            return load(path)
        except FileNotFoundError:
            self.main.fail(f"no such policy file: {path}",
                           hint=f"sharness-ai policy new {path} writes one, from five questions", code=EXIT_ERROR)
        except (PolicyError, OSError) as e:
            self.main.fail(f"policy: {e}", hint="a policy is one small JSON object; sharness-ai policy new "
                                                "writes a well-formed one", code=EXIT_ERROR)
        return None

    def _show(self, path: str, policy: dict, problems: list = ()) -> list:
        d = self.main.draw
        lines = d.kv("policy", f"{policy.get('id', '?')}   {path}", style="bold")
        return lines + d.policy(policy, None if problems else policy_hash(policy), problems)

    def _lower(self, path: str, doc: dict):
        """A levelled document (level 3, 4 or 5) compiled to its v0; the chain's hashes drawn.
        Returns (v0, lines) or (doc, []) for a plain v0 policy; raises PolicyError."""
        from sharness_ai.level import Chain, level_of
        lv = level_of(doc) if "level" in doc else 2
        if lv == 2:
            return doc, []
        chain = Chain.from_document(doc)
        d = self.main.draw
        lines = d.kv("level", f"{lv}: {chain.top.hash}   compiled to the v0 policy below "
                              f"({' → '.join(d.hash_short(s.hash) for s in chain.steps if s.level >= 2)})", style="accent")
        for i, u in enumerate([u for s in chain.steps for u in s.unheld]):
            lines += d.kv("not held" if i == 0 else "", u, style="warn" if i == 0 else None)
        return chain.v0, lines

    # ---- hash, check, show --------------------------------------------------------------------
    def cmd_hash(self, args) -> int:
        policy = self._load(args.file)
        if policy is None:
            return EXIT_ERROR
        print(policy_hash(policy))
        return 0

    def cmd_check(self, args) -> int:
        policy = self._load(args.file)
        if policy is None:
            return EXIT_ERROR
        try:
            policy, level_lines = self._lower(args.file, policy)
        except PolicyError as e:
            return self.main.fail(str(e), hint="a levelled document compiles to a v0 policy; the message names the row", code=EXIT_PROBLEMS)
        problems = check(policy)
        t, d = self.main.term, self.main.draw
        if self.main.json:
            print(json.dumps({"file": args.file, "problems": problems, "advice": advice(policy) if not problems else [],
                              "hash": policy_hash(policy) if not problems else None}, indent=1))
            return EXIT_PROBLEMS if problems else 0
        lines = level_lines + self._show(args.file, policy, problems)
        if problems:
            lines += d.kv("result", f"{len(problems)} problem(s): not a well-formed v0 policy; run would refuse it", style="no")
            lines += d.kv("next", "fix the rows marked above, then sharness-ai policy check again", style="head")
            t.write(*lines)
            return EXIT_PROBLEMS
        lines += d.kv("result", f"well-formed v0 policy: {summary(policy)}", style="ok")
        for i, a in enumerate(advice(policy)):
            lines += d.kv("advice" if i == 0 else "", a)
        lines += d.kv("next", f"sharness-ai run --policy {args.file} --expect-hash {policy_hash(policy)} -- CMD", style="head", wrap=False)
        t.write(*lines)
        return 0

    def cmd_show(self, args) -> int:
        policy = self._load(args.file)
        if policy is None:
            return EXIT_ERROR
        try:
            policy, level_lines = self._lower(args.file, policy)
        except PolicyError as e:
            return self.main.fail(str(e), code=EXIT_ERROR)
        if self.main.json:
            print(json.dumps({"file": args.file, "policy": policy, "hash": policy_hash(policy)}, indent=1))
            return 0
        lines = level_lines + self._show(args.file, policy, check(policy)) + self.main.draw.caveat()
        self.main.term.write(*lines)
        return 0

    # ---- translate ----------------------------------------------------------------------------
    def cmd_translate(self, args) -> int:
        from sharness_ai.translate import translate
        policy = self._load(args.file)
        if policy is None:
            return EXIT_ERROR
        problems = check(policy)
        if problems:
            print(f"sharness-ai policy: {args.file} is not well-formed: " + "; ".join(problems), file=sys.stderr)
            return EXIT_PROBLEMS
        cmd = args.target_argv
        text, notes = translate(policy, args.to, tuple(cmd) if cmd else ("/bin/sh", "-c", "echo hello"))
        if not args.notes:
            print(text)
            print()
        print(f"# {args.to}: not enforced from policy {policy.get('id')} ({policy_hash(policy)[:19]}…):")
        for n in notes:
            print(f"#   - {n}")
        return 0

    # ---- new: the wizard ----------------------------------------------------------------------
    def defaults(self) -> dict:
        cwd = os.path.realpath(os.getcwd())
        return {"read": _existing(SYSTEM) + [cwd], "write": [], "exec": _existing(SYSTEM),
                "ports": [], "memory": 256, "pids": 16}

    def _ask_edge(self, edge: str, current, n: int = None, of: int = None):
        """One question, shown with its default; the answer parsed as the edge's type."""
        pm = self.main.prompt
        prefix = f"{n}/{of}  " if n else ""
        if edge in ("read", "write", "exec"):
            shown = " ".join(current) if current else "nowhere"
            raw = pm.ask(QUESTIONS[edge], default=shown, prefix=prefix,
                         hint="paths, space-separated; 'none' for nowhere" if edge == "write" else "")
            return _list(raw) if raw != shown else list(current)
        if edge == "ports":
            shown = " ".join(map(str, current)) if current else "none"
            raw = pm.ask(QUESTIONS[edge], default=shown, prefix=prefix, hint="e.g. 443, or 'none'")
            return [int(x) for x in _list(raw)] if raw != shown else list(current)
        raw = pm.ask(QUESTIONS[edge], default=str(current), prefix=prefix, hint="0 for no cap")
        return int(raw)

    def _assemble(self, pid: str, e: dict) -> dict:
        proc = {"no_new_privs": True}
        if e["memory"]:
            proc["max_memory_mb"] = e["memory"]
        if e["pids"]:
            proc["max_pids"] = e["pids"]
        return {"pbp": 1, "id": pid, "layer": "invocation",
                "notes": "written by sharness-ai policy new; review every row: the hash names exactly these",
                "files": {"read": sorted(set(e["read"])), "write": sorted(set(e["write"])), "exec": sorted(set(e["exec"]))},
                "network": "none" if not e["ports"] else {"connect_tcp_ports": sorted(set(e["ports"]))},
                "process": proc}

    def _write(self, path: str, policy: dict) -> int:
        problems = check(policy)
        t, d = self.main.term, self.main.draw
        if problems:
            t.write(*self._show(path, policy, problems))
            t.write(*d.kv("result", "not written: fix the rows above", style="no"))
            return EXIT_PROBLEMS
        with open(path, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=1)
            f.write("\n")
        h = policy_hash(policy)
        self.main.state.record("policy", file=os.path.abspath(path), id=policy["id"], hash=h)
        t.write(*self._show(path, policy))
        t.write(*d.kv("written", f"{path}   {h}", style="ok"))
        t.write(*d.kv("next", f"sharness-ai run --policy {path} --expect-hash {h} -- CMD", style="head", wrap=False))
        return 0

    def cmd_new(self, args) -> int:
        path = args.file
        if os.path.exists(path) and not args.force:
            return self.main.fail(f"{path} exists; nothing written",
                                  hint=f"--force overwrites it; sharness-ai policy edit {path} changes one edge",
                                  code=EXIT_ERROR)
        e = self.defaults()
        given = {"read": args.read, "write": args.write, "exec": args.exec, "ports": args.ports,
                 "memory": args.memory, "pids": args.pids}
        for k, v in given.items():
            if v is not None:
                e[k] = _list(v) if k in ("read", "write", "exec") else [int(x) for x in _list(v)] if k == "ports" else int(v)
        t = self.main.term
        t.write(*self.main.draw.head("policy new", f"five questions write {path}; every default is shown before it is accepted"))
        if not args.yes:
            for n, k in enumerate(("read", "write", "exec", "ports", "memory"), 1):
                if given[k] is None:
                    try:
                        e[k] = self._ask_edge(k, e[k], n, 5)
                    except ValueError as ex:
                        return self.main.fail(f"{QUESTIONS[k]} {ex}", hint="ports and caps are whole numbers", code=EXIT_ERROR)
        pid = args.id or os.path.splitext(os.path.basename(path))[0]
        return self._write(path, self._assemble(pid, e))

    # ---- edit: one edge, and the name changes ---------------------------------------------------
    def cmd_edit(self, args) -> int:
        policy = self._load(args.file)
        if policy is None:
            return EXIT_ERROR
        before = policy_hash(policy)
        files = policy.setdefault("files", {"read": [], "write": [], "exec": []})
        net = policy.get("network")
        proc = policy.setdefault("process", {"no_new_privs": True})
        current = {"read": files.get("read", []), "write": files.get("write", []), "exec": files.get("exec", []),
                   "ports": [] if net == "none" or not isinstance(net, dict) else net.get("connect_tcp_ports", []),
                   "memory": proc.get("max_memory_mb") or 0, "pids": proc.get("max_pids") or 0}
        edge = args.edge or self.main.prompt.choose("which edge?", [(k, QUESTIONS[k]) for k in EDGES], default="write")
        try:
            value = _list(args.value) if args.value is not None and edge in ("read", "write", "exec") else \
                [int(x) for x in _list(args.value)] if args.value is not None and edge == "ports" else \
                int(args.value) if args.value is not None else self._ask_edge(edge, current[edge])
        except ValueError as ex:
            return self.main.fail(f"{QUESTIONS[edge]} {ex}", hint="ports and caps are whole numbers", code=EXIT_ERROR)
        if edge in ("read", "write", "exec"):
            files[edge] = sorted(set(value))
        elif edge == "ports":
            policy["network"] = "none" if not value else {"connect_tcp_ports": sorted(set(value))}
        elif edge == "memory":
            proc.pop("max_memory_mb", None)
            if value:
                proc["max_memory_mb"] = value
        else:
            proc.pop("max_pids", None)
            if value:
                proc["max_pids"] = value
        code = self._write(args.file, policy)
        if code == 0:
            d = self.main.draw
            self.main.term.write(*d.kv("renamed", f"{d.hash_short(before)} {self.main.term.glyph('arrow')} "
                                                  f"{d.hash_short(policy_hash(policy))}: a row changed, so the name changed",
                                       style="accent"))
        return code
