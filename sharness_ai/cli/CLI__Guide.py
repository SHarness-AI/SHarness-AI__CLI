"""`sharness-ai` with no arguments on a terminal, or `sharness-ai guide`: where you are, the
ladder of steps and which you have climbed, the policy in the current directory if there is
one, and a menu. On a pipe the screen prints once with no menu."""
import glob
import os

from sharness_ai._version import VERSION
from sharness_ai.cli.CLI__Probe import CLI__Probe
from sharness_ai.policy import PolicyError, check, load, policy_hash
from sharness_ai.probe import probe

MENU = (("1", "probe", ["probe"]), ("2", "hello", ["hello"]), ("3", "new policy", ["policy", "new"]),
        ("4", "run a command", None), ("5", "translate", None), ("6", "components", ["components"]),
        ("7", "doctor", ["doctor"]), ("q", "quit", None))
MAX_SCAN = 40


class CLI__Guide:
    def __init__(self, main):
        self.main = main

    def _policy_here(self):
        """The policy to draw: the last one written if it still exists, else the first well-formed
        v0 policy among the JSON files of the current directory (a few, not a crawl)."""
        last = self.main.state.get("policy").get("file")
        candidates = ([last] if last and os.path.isfile(last) else []) + sorted(glob.glob("*.json"))[:MAX_SCAN]
        for path in candidates:
            try:
                policy = load(path)
            except (PolicyError, OSError):
                continue
            if not check(policy):
                return path, policy
        return None, None

    def _ladder(self, p: dict) -> list:
        s = self.main.state
        hello = s.get("hello")
        pol = s.get("policy")
        run = s.get("run")
        linux = p["os"].startswith("linux") and bool(p["landlock_abi"])
        return [
            (True, 1, "probe", "the grant: what a process here can do before any policy"),
            (bool(hello) if linux else None, 2, "hello",
             f"the acceptance test: {hello['held']}/{hello['of']} held on {hello['at']}" if hello
             else "the acceptance test: six probes under one policy" if linux
             else "needs a Linux kernel with Landlock: refuses here, nothing runs"),
            (bool(pol), 3, "policy", f"{pol['id']}  {self.main.draw.hash_short(pol['hash'])}" if pol
             else "write one for your tool: sharness-ai policy new my-tool.json"),
            (bool(run), 4, "run", f"last: {run['id']} exit {run['exit']} on {run['at']}" if run
             else "your command under it: sharness-ai run --policy FILE -- CMD"),
        ]

    def screen(self) -> list:
        m = self.main
        t, d = m.term, m.draw
        with m.trace.step("probe"):
            p = probe()
        sep = f" {t.glyph('dot')} "
        lines = d.banner(VERSION)
        lines.append("")
        lines += d.kv("where you are", CLI__Probe.where(p, sep), style="bold")
        for r in CLI__Probe.readings(p)[:2]:
            lines += d.kv("", r)
        lines.append("")
        steps = d.ladder(self._ladder(p))
        lines += d.kv("the ladder", steps[0], style="bold")
        for s in steps[1:]:
            lines += d.kv("", s)
        path, policy = self._policy_here()
        if policy:
            rel = os.path.relpath(path)
            shown = rel if not rel.startswith("..") else path
            lines.append("")
            lines += d.kv("the policy", f"{policy.get('id')}   {shown}", style="bold")
            lines += d.policy(policy, policy_hash(policy))
        return lines

    def _argv_for(self, key: str):
        for k, _, argv in MENU:
            if k == key:
                if argv is not None:
                    return argv
                if key == "4":
                    path = self.main.prompt.ask("which policy file?", default=self._policy_here()[0] or "policy.json")
                    cmd = self.main.prompt.ask("which command?", default="sh -c 'echo hello from under a policy'")
                    return ["run", "--policy", path, "--", "sh", "-c", cmd] if " " in cmd else ["run", "--policy", path, "--", cmd]
                if key == "5":
                    path = self.main.prompt.ask("which policy file?", default=self._policy_here()[0] or "policy.json")
                    to = self.main.prompt.choose("to which enforcer?", [(x, x) for x in ("bwrap", "docker", "claude-code", "kubernetes", "landlock")], default="docker")
                    return ["policy", "translate", path, "--to", to]
        return None

    def cmd_guide(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        while True:
            t.write(*self.screen())
            if not (t.interactive or m.prompt.answers) or getattr(args, "once", False):
                t.write("")
                t.write(*d.kv("next", "sharness-ai hello   then sharness-ai policy new my-tool.json; sharness-ai --help lists everything", style="head"))
                return 0
            t.write("")
            t.write(*d.kv("what next?", d.menu([(k, label) for k, label, _ in MENU]), style="head"))
            choice = m.prompt.ask("", default="q", prefix="> ").strip().lower()
            if choice in ("q", "quit", "exit", ""):
                return 0
            argv = self._argv_for(choice)
            if argv is None:
                t.write(f"  {t.mark('no')} {choice!r} is not on the menu")
                continue
            t.write("")
            m.dispatch(argv)
            t.write("")
