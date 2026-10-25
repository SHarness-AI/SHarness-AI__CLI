"""sharness-ai: the SHarness command line tool (https://sharness.ai).

Status: experiments. Nothing here is a SHarness component. The commands are the first
experiments from the design, small enough to read in one sitting (experiments/README.md):

    probe                      E01  the grant: what a process here can do before any policy
    policy hash FILE           E02  the one value the person supplies: canonical JSON → sha256
    policy check FILE               the shape of a v0 policy
    policy translate FILE --to T    E10  the same policy as bwrap, docker, claude-code, kubernetes; and the gap
    run --policy FILE -- CMD   E03  one command under a policy: Landlock + no network
    hello                      E04  the memo's acceptance test, for one child process
"""
import argparse
import json
import sys

from sharness_ai._version import VERSION


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sharness-ai",
        description="sharness-ai: the SHarness command line tool (https://sharness.ai). "
                    "Status: experiments; no SHarness component is built yet.")
    parser.add_argument("--version", action="version", version=f"sharness-ai {VERSION}")
    sub = parser.add_subparsers(dest="cmd", metavar="command")

    p = sub.add_parser("probe", help="E01: the grant, what a process here can do before any policy")
    p.add_argument("--json", action="store_true", help="machine-readable output")

    pol = sub.add_parser("policy", help="E02: hash or check a Process Behaviour Policy (v0)")
    pol_sub = pol.add_subparsers(dest="policy_cmd", metavar="action")
    ph = pol_sub.add_parser("hash", help="print sha256:… of the canonical policy")
    ph.add_argument("file")
    pc = pol_sub.add_parser("check", help="check the shape of a v0 policy")
    pc.add_argument("file")
    pt = pol_sub.add_parser("translate", help="E10: write the policy in another enforcer's form, with what it does not enforce")
    pt.add_argument("file")
    pt.add_argument("--to", required=True, choices=("bwrap", "docker", "claude-code", "kubernetes", "landlock"))
    pt.add_argument("--notes", action="store_true", help="print only what the target does not enforce")
    pt.add_argument("target_argv", nargs="*", metavar="CMD",
                    help="after --: the command to wrap (for bwrap, docker, kubernetes, landlock)")

    r = sub.add_parser("run", help="E03: run one command under a policy (Linux, Landlock)")
    r.add_argument("--policy", required=True, help="the policy file (JSON)")
    r.add_argument("--expect-hash", help="refuse unless the policy hashes to this (sha256:…)")
    r.add_argument("--verbose", action="store_true")
    r.add_argument("argv", nargs=argparse.REMAINDER, help="-- the command and its arguments")

    h = sub.add_parser("hello", help="E04: the memo's acceptance test, for one child process")
    h.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    target = None
    if argv[:2] == ["policy", "translate"] and "--" in argv:
        # split off the wrapped command ourselves: argparse before 3.12 rejects `-- CMD` after an option
        i = argv.index("--")
        argv, target = argv[:i], argv[i + 1:]
    args = parser.parse_args(argv)
    if target is not None:
        args.target_argv = target
    if args.cmd is None:
        parser.print_help()
        return 0
    if args.cmd == "probe":
        from sharness_ai.probe import probe, render
        p = probe()
        print(json.dumps(p, indent=1) if args.json else render(p))
        return 0
    if args.cmd == "policy":
        from sharness_ai.policy import PolicyError, check, load, policy_hash, summary
        if args.policy_cmd is None:
            parser.parse_args(["policy", "--help"])
            return 0
        try:
            policy = load(args.file)
            if args.policy_cmd == "hash":
                print(policy_hash(policy))
                return 0
            if args.policy_cmd == "translate":
                from sharness_ai.translate import translate
                problems = check(policy)
                if problems:
                    print(f"sharness-ai policy: {args.file} is not well-formed: " + "; ".join(problems), file=sys.stderr)
                    return 1
                cmd = args.target_argv
                text, notes = translate(policy, args.to, tuple(cmd) if cmd else ("/bin/sh", "-c", "echo hello"))
                if not args.notes:
                    print(text)
                    print()
                print(f"# {args.to}: not enforced from policy {policy.get('id')} ({policy_hash(policy)[:19]}…):")
                for n in notes:
                    print(f"#   - {n}")
                return 0
            problems = check(policy)
        except PolicyError as e:
            print(f"sharness-ai policy: {e}", file=sys.stderr)
            return 2
        if problems:
            print(f"{args.file}: {len(problems)} problem(s)")
            for x in problems:
                print(f"  ✗ {x}")
            return 1
        print(f"{args.file}: well-formed v0 policy, id {policy['id']}: {summary(policy)}; {policy_hash(policy)}")
        return 0
    if args.cmd == "run":
        from sharness_ai.policy import PolicyError, load
        from sharness_ai.run import run
        cmd = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
        try:
            policy = load(args.policy)
        except (PolicyError, OSError) as e:
            print(f"sharness-ai run: {e}", file=sys.stderr)
            return 125
        return run(policy, cmd, expect_hash=args.expect_hash, verbose=args.verbose)
    if args.cmd == "hello":
        from sharness_ai.hello import hello
        return hello(as_json=args.json)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
