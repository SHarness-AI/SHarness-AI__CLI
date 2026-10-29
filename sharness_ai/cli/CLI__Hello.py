"""`sharness-ai hello`: the acceptance test as a scoreboard. The six probes and the JSON are
hello.measure()'s, unchanged; this draws the policy once, one verdict row per probe with who
refused, a result bar, and the two things to do with the result."""
import json
import time

from sharness_ai import hello as engine
from sharness_ai.run import EXIT_APPLY, unavailable

WHO = {"allowed": "allowed", "refused": "refused by the kernel", "inconclusive": "inconclusive",
       "ran": "RAN: sharness-ai did not refuse", "failed": "failed otherwise"}
TARGETS = {"read": "/usr (listing)",
           "write-tmp": "/tmp/…tmp (create)",       # noqa: S108 - the probe's target, as a label  # nosec B108
           "write-cwd": "./…tmp (create)", "net": "1.1.1.1:443 (connect)", "memory": "400 MiB under 128",
           "hash": "sha256:0000… (--expect-hash)"}


class CLI__Hello:
    def __init__(self, main):
        self.main = main

    @staticmethod
    def _verdict(r: dict) -> tuple:
        got = r["got"]
        kind = got.split(" ", 1)[0]
        detail = got[len(kind):].strip(" ()")
        if got.startswith(r["expected"]):
            mark = "ok"
        elif kind == "inconclusive":
            mark = "ask"
        else:
            mark = "no"
        who = WHO.get(kind, kind)
        if kind == "refused" and r["probe"] == "hash":
            who = "refused by sharness-ai"
        if kind == "refused" and "MemoryError" in detail:
            who = "refused by the kernel (MemoryError)"
        elif kind == "refused" and ("EACCES" in detail or "Permission denied" in detail):
            who = "refused by the kernel (EACCES)"
        return mark, who, detail

    def cmd_hello(self, args) -> int:
        m = self.main
        reason = unavailable()
        t, d = m.term, m.draw
        if reason:
            if m.json:
                print(json.dumps({"experiment": "E04 hello", "refused": reason}))
            else:
                t.write(*d.head("hello", "the acceptance test: six probes under one policy"))
                t.write(*d.kv("refused", f"Nothing ran. {reason[0].upper()}{reason[1:]}", style="no"))
                t.write(*d.kv("next", "the Linux tab of the playground has a kernel: "
                                      "https://sharness.ai/code/playground/index.html", style="head"))
            return EXIT_APPLY
        with m.trace.step("hello: six probes"):
            r = engine.measure()
        m.state.record("hello", held=r["held"], of=r["of"], landlock_abi=r["landlock_abi"])
        if m.json:
            print(json.dumps(r, indent=1))
            return 0 if not r["failed"] else 1
        sep = f" {t.glyph('dot')} "
        lines = d.head("hello", "experiment E04: the memo's acceptance test, for one child process")
        lines += d.kv("policy", f"{r['policy_id']}   generated for this interpreter and this directory", style="bold")
        lines += d.policy(r["policy"], r["policy_hash"])
        netns = "yes (uid 0)" if r["euid"] == 0 else "only through a user namespace; else Landlock TCP rules (not UDP)"
        lines += d.kv("kernel", sep.join([f"Landlock ABI {r['landlock_abi'] or 'none'}", f"empty network namespace: {netns}"]))
        lines.append("")
        for x in r["results"]:
            mark, who, detail = self._verdict(x)
            note = "" if mark == "ok" else f"expected {x['expected']}" + (f"; {detail}" if detail else "")
            lines.append(d.row(mark, x["probe"], TARGETS.get(x["probe"], ""), who, note))
        lines.append("")
        tail = f", {r['inconclusive']} inconclusive" if r["inconclusive"] else ""
        when = time.strftime("%d %b %Y", time.gmtime())
        style = "ok" if not r["failed"] and not r["inconclusive"] else "warn" if not r["failed"] else "no"
        lines += d.kv("result", f"{d.bar(r['held'], r['of'])} {r['held']}/{r['of']} held{tail}"
                                f"{sep}measured {when}, Landlock ABI {r['landlock_abi']}", style=style)
        lines += d.kv("not covered", r["not_covered"], style="dim")
        lines += d.kv("report", f"sharness-ai hello --json, then paste it at {r['report']}: every machine is a row on "
                                "sharness.ai/evidence/machines; a refusal that did not happen is the most useful report")
        lines += d.caveat()
        nxt = ("sharness-ai policy new my-tool.json   write a policy for your own tool, from five questions"
               if not r["failed"] else "sharness-ai probe   says what this kernel has; please report the result")
        lines += d.kv("next", nxt, style="head")
        t.write(*lines)
        return 0 if not r["failed"] else 1
