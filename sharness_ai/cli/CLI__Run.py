"""`sharness-ai run`: the plan, then the command. The plan and the rules go to stderr so the
tool's own stdout stays what it was; `--quiet` leaves only the tool's output; `--verbose` draws
the policy before the command starts."""
import sys
import time

from sharness_ai import run as engine
from sharness_ai.policy import PolicyError, check, load, policy_hash
from sharness_ai.ui.Draw import Draw
from sharness_ai.ui.Term import Term

HINTS = {
    engine.EXIT_REFUSED: "the policy or the hash was refused and nothing ran: sharness-ai policy check FILE "
                         "and sharness-ai policy hash FILE say which",
    engine.EXIT_APPLY:   "the policy could not be applied here and nothing ran: sharness-ai probe says what "
                         "this kernel has; --best-effort runs anyway and says what is NOT enforced",
}


class CLI__Run:
    def __init__(self, main):
        self.main = main

    def _plan_lines(self, draw: Draw, policy: dict, h: str, verbose: bool) -> list:
        t = draw.t
        sep = f" {t.glyph('dot')} "
        p = engine.plan(policy)
        abi = p["landlock_abi"]
        net = policy.get("network")
        how_net = ("empty network namespace, else Landlock TCP rules" if net == "none" else
                   f"Landlock TCP rules for ports {p['ports']}" if p["landlock_tcp"] else
                   f"ports NOT enforceable at ABI {abi}")
        lines = [t.style("sharness-ai run", "bold") + f"  {policy.get('id')}  {t.style(h, 'accent')}"]
        lines += draw.kv("enforced by", sep.join([f"Landlock ABI {abi}: files", how_net, "rlimits, and a cgroup where one can be made"]))
        gaps = ["UDP (DNS) unless the namespace applied", "Unix sockets by path", "the inherited environment"]
        lines += draw.kv("not covered", sep.join(gaps), style="dim")
        if verbose:
            lines += draw.policy(policy, None)
        return lines

    def cmd_run(self, args) -> int:
        m = self.main
        argv = args.argv[1:] if args.argv[:1] == ["--"] else list(args.argv)
        try:
            policy = load(args.policy)
        except FileNotFoundError:
            print(f"sharness-ai run: no such policy file: {args.policy}. Nothing ran.", file=sys.stderr)
            print(f"  hint: sharness-ai policy new {args.policy} writes one", file=sys.stderr)
            return engine.EXIT_REFUSED
        except (PolicyError, OSError) as e:
            print(f"sharness-ai run: {e}. Nothing ran.", file=sys.stderr)
            return engine.EXIT_REFUSED
        h = policy_hash(policy)
        quiet = args.quiet or m.json
        term = Term.detect(plain=m.plain, width=m.width_arg, err=True)
        draw = Draw(term)
        will_run = not check(policy) and not engine.unavailable() and (args.expect_hash in (None, h))
        if not quiet and will_run:
            term.write(*self._plan_lines(draw, policy, h, args.verbose))
            term.write(draw.rule(f"{argv[0] if argv else '?'} starts"))
        t0 = time.monotonic()
        with m.trace.step("run"):
            code = engine.run(policy, argv, expect_hash=args.expect_hash, verbose=args.verbose,
                              best_effort=args.best_effort)
        secs = time.monotonic() - t0
        m.state.record("run", policy=args.policy, id=policy.get("id"), hash=h, exit=code)
        if code in HINTS:
            print(f"  hint: {HINTS[code]}", file=sys.stderr)
        elif not quiet:
            verdict = "exit 0" if code == 0 else f"exit {code}"
            term.write(draw.rule(f"{argv[0] if argv else '?'} {verdict} {term.glyph('dot')} {secs:.1f} s"))
            term.write(*draw.kv("next", f"sharness-ai policy translate {args.policy} --to docker -- CMD carries the "
                                         f"same policy to another enforcer, with what it cannot enforce", style="dim"))
        return code
