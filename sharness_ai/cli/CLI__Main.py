"""The front door: one parser, one dispatch, one place that turns an exception into a sentence
with a hint. Holds one object per command group (the sgit shape); each subcommand is bound to
its `cmd_*` method with set_defaults(func=...), so there is no `if` ladder here.

    sharness-ai                         the guide (a terminal), or the usage text (a pipe)
    probe | hello | run | policy …      the experiments, as before, drawn
    doctor                              can a policy hold here? seven checks with their fixes
    contain | profile | explain         the levels: a sentence (5), a role (4), any document drawn down (all)
    help [--format json]                the command surface, from the parser itself
    components [NAME] · bash net kms llm launcher    the map; verbs that say "not built" (exit 69)
    session · fs · door                 E05 and the first door: sharness.fs.disk and its twin
"""
import argparse
import sys

from sharness_ai._version import VERSION
from sharness_ai.cli.CLI__Components import ORDER, CLI__Components
from sharness_ai.cli.CLI__Doctor import CLI__Doctor
from sharness_ai.cli.CLI__Door import CLI__Door
from sharness_ai.cli.CLI__Fs import DEFAULT_PORT, CLI__Fs
from sharness_ai.cli.CLI__Guide import CLI__Guide
from sharness_ai.cli.CLI__Hello import CLI__Hello
from sharness_ai.cli.CLI__Level import CLI__Level
from sharness_ai.cli.CLI__Policy import CLI__Policy
from sharness_ai.cli.CLI__Probe import CLI__Probe
from sharness_ai.cli.CLI__Reference import CLI__Reference
from sharness_ai.cli.CLI__Run import CLI__Run
from sharness_ai.cli.CLI__Session import CLI__Session
from sharness_ai.cli.CLI__State import CLI__State
from sharness_ai.door.Session import Session
from sharness_ai.ui import Draw, Prompt, Term, Trace

S = argparse.SUPPRESS       # a flag repeated on a subparser must not reset the global one
EXIT_INTERRUPTED = 130
TRANSLATE_TARGETS = ("bwrap", "docker", "claude-code", "kubernetes", "landlock")


class CLI__Main:
    def __init__(self, term: Term = None, answers: list = None, state_path: str = None):
        self._term = term
        self._answers = answers
        self.state = CLI__State(state_path)
        self.trace = Trace()
        self.json = self.plain = self.debug = False
        self.width_arg = None
        self.probe = CLI__Probe(self)
        self.policy = CLI__Policy(self)
        self.runner = CLI__Run(self)
        self.hello = CLI__Hello(self)
        self.components = CLI__Components(self)
        self.guide = CLI__Guide(self)
        self.doctor = CLI__Doctor(self)
        self.reference = CLI__Reference(self)
        self.level = CLI__Level(self)
        self.session = CLI__Session(self)
        self.fs = CLI__Fs(self)
        self.door = CLI__Door(self)

    # ---- the parser -----------------------------------------------------------------------------
    def build_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="sharness-ai",
            description="sharness-ai: the SHarness command line tool (https://sharness.ai). "
                        "Status: experiments; no SHarness component is built yet. With no command, on a "
                        "terminal, it draws where you are and what to do next.")
        parser.add_argument("--version", action="version", version=f"sharness-ai {VERSION}")
        parser.add_argument("--json", action="store_true", help="machine-readable output, on every command that has it")
        parser.add_argument("--plain", action="store_true", help="ASCII only, no colour (also: NO_COLOR, SHARNESS_AI_PLAIN=1, a pipe)")
        parser.add_argument("--debug", action="store_true", help="the steps and their timings, and the traceback on an error")
        parser.add_argument("--width", type=int, default=None, help="draw for this many columns")
        sub = parser.add_subparsers(dest="cmd", metavar="command")

        g = sub.add_parser("guide", help="where you are, the ladder, and what to do next (the no-arguments screen)")
        g.add_argument("--once", action="store_true", help="draw once, no menu")
        g.set_defaults(func=self.guide.cmd_guide)

        c5 = sub.add_parser("contain", help="level 5: one sentence (a workspace, sites, secrets) compiled to the kernel and run")
        c5.add_argument("--workspace", default=".", help="the folder the agent may write (default: here)")
        c5.add_argument("--sites", nargs="*", help="host names it may reach (held as ports until sharness.net runs)")
        c5.add_argument("--secrets", nargs="*", help="secret names it may use (not held yet: named as unheld)")
        c5.add_argument("--profile", default="coding-agent", help="the level-4 profile (sharness-ai profile list)")
        c5.add_argument("--agent", help="the agent's name (default: the command)")
        c5.add_argument("--memory-mb", type=int, dest="memory_mb")
        c5.add_argument("--pids", type=int)
        c5.add_argument("--save", help="write the level-5 document here")
        c5.add_argument("--expect-hash", help="refuse unless the sentence hashes to this")
        c5.add_argument("--dry-run", action="store_true", help="compile and print; run nothing")
        c5.add_argument("argv", nargs=argparse.REMAINDER, help="-- the agent's command")
        c5.set_defaults(func=self.level.cmd_contain)

        pf = sub.add_parser("profile", help="level 4: the roles a vendor ships, with the blanks a person fills")
        pfs = pf.add_subparsers(dest="profile_cmd", metavar="action")
        pfs.add_parser("list", help="the profiles here").set_defaults(func=self.level.cmd_profile)
        x = pfs.add_parser("show", help="one profile: its blanks and its level-3 template")
        x.add_argument("name")
        x.set_defaults(func=self.level.cmd_profile)
        pf.set_defaults(func=self.level.cmd_profile)

        ex = sub.add_parser("explain", help="any document, drawn down the levels to the kernel, hash by hash")
        ex.add_argument("file")
        ex.set_defaults(func=self.level.cmd_explain)

        dr = sub.add_parser("doctor", help="can a policy hold here? eight checks in order, each with what to do about it")
        dr.add_argument("--json", action="store_true", default=S)
        dr.set_defaults(func=self.doctor.cmd_doctor)

        hp = sub.add_parser("help", help="every command, read from the parser itself; --format json for a page or a diff")
        hp.add_argument("--format", choices=("text", "json"), default="text")
        hp.set_defaults(func=self.reference.cmd_help)

        p = sub.add_parser("probe", help="E01: the grant, what a process here can do before any policy")
        p.add_argument("--json", action="store_true", default=S, help="machine-readable output")
        p.set_defaults(func=self.probe.cmd_probe)

        pol = sub.add_parser("policy", help="E02: hash, check, show, translate, write (new) or change (edit) a Process Behaviour Policy")
        ps = pol.add_subparsers(dest="policy_cmd", metavar="action")
        x = ps.add_parser("hash", help="print sha256:… of the canonical policy, its name")
        x.add_argument("file")
        x.set_defaults(func=self.policy.cmd_hash)
        x = ps.add_parser("check", help="the shape of a v0 policy, drawn, with problems on their rows and advice")
        x.add_argument("file")
        x.add_argument("--json", action="store_true", default=S)
        x.set_defaults(func=self.policy.cmd_check)
        x = ps.add_parser("show", help="draw the policy: one process, its edges, its hash")
        x.add_argument("file")
        x.add_argument("--json", action="store_true", default=S)
        x.set_defaults(func=self.policy.cmd_show)
        x = ps.add_parser("translate", help="E10: the policy in another enforcer's form, with what it does not enforce")
        x.add_argument("file")
        x.add_argument("--to", required=True, choices=TRANSLATE_TARGETS)
        x.add_argument("--notes", action="store_true", help="print only what the target does not enforce")
        x.add_argument("target_argv", nargs="*", metavar="CMD", help="after --: the command to wrap")
        x.set_defaults(func=self.policy.cmd_translate)
        x = ps.add_parser("new", help="write a policy from five questions; every default is shown before it is accepted")
        x.add_argument("file", nargs="?", default="policy.json")
        x.add_argument("--id", help="the policy's id (default: the file name)")
        for k, h in (("read", "paths it may read"), ("write", "paths it may write"), ("exec", "paths it may run"),
                     ("ports", "TCP ports it may connect to"), ("memory", "memory cap in MiB (0: none)"),
                     ("pids", "process cap (0: none)")):
            x.add_argument(f"--{k}", help=f"{h}; answers the question without asking")
        x.add_argument("--yes", "-y", action="store_true", help="accept every default that was not given")
        x.add_argument("--force", action="store_true", help="overwrite an existing file")
        x.set_defaults(func=self.policy.cmd_new)
        x = ps.add_parser("edit", help="change one edge of a policy and see its name change")
        x.add_argument("file")
        x.add_argument("--edge", choices=("read", "write", "exec", "ports", "memory", "pids"))
        x.add_argument("--value", help="the new value; asked for when absent")
        x.set_defaults(func=self.policy.cmd_edit)

        r = sub.add_parser("run", help="E03: run one command under a policy (Linux, Landlock)")
        r.add_argument("--policy", required=True, help="the policy file (JSON)")
        r.add_argument("--expect-hash", help="refuse unless the policy hashes to this (sha256:…)")
        r.add_argument("--verbose", action="store_true", help="draw the policy and say what was applied")
        r.add_argument("--quiet", action="store_true", help="only the command's own output")
        r.add_argument("--best-effort", action="store_true",
                       help="run even when a row of the policy cannot be enforced here (it is said on stderr); "
                            "without this flag such a policy is refused and nothing runs")
        r.add_argument("argv", nargs=argparse.REMAINDER, help="-- the command and its arguments")
        r.set_defaults(func=self.runner.cmd_run)

        h = sub.add_parser("hello", help="E04: the acceptance test, six probes under one policy, as a scoreboard")
        h.add_argument("--json", action="store_true", default=S, help="machine-readable output")
        h.set_defaults(func=self.hello.cmd_hello)

        c = sub.add_parser("components", help="the operating system a process sees: the map, with status")
        c.add_argument("name", nargs="?", choices=ORDER, help="one component in detail (exits 69 when not built)")
        c.set_defaults(func=self.components.cmd_components)
        for name in ORDER[:-1]:
            if name == "fs":
                continue
            v = sub.add_parser(name, help=f"sharness.{name}: designed, not built; the map and the proposed surface (exit 69)")
            v.set_defaults(func=self.components.cmd_components, name=name)

        se = sub.add_parser("session", help="E05: a session CA and one identity per role (openssl); what doors and callers load")
        ses = se.add_subparsers(dest="session_cmd", metavar="action")
        x = ses.add_parser("new", help="issue the certificates and destroy the CA key")
        x.add_argument("--dir", default=Session.default_dir(), help="where the session lives")
        x.add_argument("--roles", nargs="*", help="the roles (default: app fs launcher)")
        x.add_argument("--days", type=int, default=1)
        x.set_defaults(func=self.session.cmd_new)
        x = ses.add_parser("show", help="the session's identities")
        x.add_argument("--dir", default=Session.default_dir())
        x.set_defaults(func=self.session.cmd_show)
        se.set_defaults(func=self.session.cmd_show, dir=Session.default_dir())

        fs = sub.add_parser("fs", help="sharness.fs, the only writer: serve the door (disk or disk.twin) or call it")
        fss = fs.add_subparsers(dest="fs_cmd", metavar="action")

        def common(p):
            p.add_argument("--session", default=Session.default_dir(), help="the session directory")
            p.add_argument("--port", type=int, default=DEFAULT_PORT)
        x = fss.add_parser("serve", help="run the door")
        x.add_argument("--target", choices=("disk", "disk.twin"), default="disk.twin")
        x.add_argument("--root", default=".", help="the folder the disk target owns")
        x.add_argument("--policy", help="the door's own policy: its rows (append_only, max_bytes, …)")
        x.add_argument("--audit", action="store_true", help="one JSON line per request on stderr")
        x.add_argument("--once", action="store_true", help="start, print, stop (for tests)")
        common(x)
        x.set_defaults(func=self.fs.cmd_serve)
        for name, fn, pos, src in (("hello", self.fs.cmd_hello, False, False), ("put", self.fs.cmd_put, True, True),
                                   ("append", self.fs.cmd_append, True, True), ("get", self.fs.cmd_get, True, False),
                                   ("rm", self.fs.cmd_rm, True, False), ("ls", self.fs.cmd_ls, False, False), ("log", self.fs.cmd_log, False, False)):
            x = fss.add_parser(name, help=f"{name} through the door, as the app")
            if pos:
                x.add_argument("path")
            if src:
                x.add_argument("source", nargs="?", default="-", help="a file, or stdin")
            common(x)
            x.set_defaults(func=fn)
        fs.set_defaults(func=self.components.cmd_components, name="fs")

        dr2 = sub.add_parser("door", help="the door kit: conformance of a door against its vectors")
        drs = dr2.add_subparsers(dest="door_cmd", metavar="action")
        x = drs.add_parser("conformance", help="run a door's vectors against a fresh instance (the twin first)")
        x.add_argument("name", help="sharness.fs.disk.twin or sharness.fs.disk")
        x.set_defaults(func=self.door.cmd_conformance)
        dr2.set_defaults(func=lambda a: (dr2.print_help(), 0)[1])
        return parser

    # ---- running --------------------------------------------------------------------------------
    @staticmethod
    def _split_translate(argv: list):
        """argparse before 3.12 rejects `-- CMD` after an option: split the wrapped command off."""
        if argv[:2] == ["policy", "translate"] and "--" in argv:
            i = argv.index("--")
            return argv[:i], argv[i + 1:]
        return argv, None

    def _setup(self, args):
        self.json = bool(getattr(args, "json", False))
        self.plain = bool(args.plain)
        self.debug = bool(args.debug)
        self.width_arg = args.width
        self.trace = Trace(enabled=self.debug)
        self.term = self._term or Term.detect(plain=self.plain, width=self.width_arg)
        self.draw = Draw(self.term)
        self.prompt = Prompt(self.term, self._answers)

    def fail(self, message: str, hint: str = None, code: int = 1) -> int:
        print(f"sharness-ai: error: {message}", file=sys.stderr)
        if hint:
            print(f"  hint: {hint}", file=sys.stderr)
        return code

    def dispatch(self, argv: list) -> int:
        """Run one command from a list of arguments, with the current term (the guide's menu)."""
        parser = self.build_parser()
        argv, target = self._split_translate(list(argv))
        args = parser.parse_args(argv)
        if target is not None:
            args.target_argv = target
        if args.cmd == "policy" and getattr(args, "policy_cmd", None) is None:
            parser.parse_args(["policy", "--help"])
        return args.func(args)

    def run(self, argv=None) -> int:
        parser = self.build_parser()
        argv, target = self._split_translate(list(sys.argv[1:] if argv is None else argv))
        args = parser.parse_args(argv)
        if target is not None:
            args.target_argv = target
        self._setup(args)
        if args.cmd is None:
            if self.term.interactive:
                return self.guide.cmd_guide(args)
            parser.print_help()
            return 0
        if args.cmd == "policy" and args.policy_cmd is None:
            parser.parse_args(["policy", "--help"])
            return 0
        try:
            with self.trace.step(args.cmd):
                return args.func(args)
        except KeyboardInterrupt:
            print("\ninterrupted.", file=sys.stderr)
            return EXIT_INTERRUPTED
        except FileNotFoundError as e:
            return self.fail(f"no such file: {e.filename or e}", hint="check the path; sharness-ai policy new FILE writes a policy", code=2)
        except PermissionError as e:
            return self.fail(f"permission denied: {e.filename or e}", hint="the file, or the cgroup directory, is not yours to touch", code=2)
        except Exception as e:  # noqa: BLE001 - the one place a traceback becomes a sentence
            if self.debug:
                raise
            return self.fail(f"{type(e).__name__} in {args.cmd}: {e}", hint="run again with --debug for the traceback")
        finally:
            for line in self.trace.render(self.term):
                print(line, file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    return CLI__Main().build_parser()


def main(argv=None) -> int:
    return CLI__Main().run(argv)
