"""`sharness-ai doctor`: can a policy hold here? Seven checks in order, each a small class; a
fatal failure skips the rest; every warning carries its hint; `--json` prints the report.
The lesson is the sgit CLI's doctor: a chain of checks a person reads top to bottom, with the
fix beside the failure, rather than a dump of facts."""
import json
import time

from sharness_ai.cli.doctor.Check__Kernel import Check__Kernel
from sharness_ai.cli.doctor.Check__Landlock import Check__Landlock_Files, Check__Landlock_Net
from sharness_ai.cli.doctor.Check__Limits import Check__Cgroups, Check__Process_Count
from sharness_ai.cli.doctor.Check__Doors import Check__Doors
from sharness_ai.cli.doctor.Check__Namespace import Check__Network_Namespace
from sharness_ai.cli.doctor.Check__Openssl import Check__Openssl
from sharness_ai.cli.doctor.Check__Result import FAIL, PASS, SKIP, WARN, Check__Result
from sharness_ai.cli.doctor.Check__Write_Probe import Check__Write_Probe

CHECKS = (Check__Kernel, Check__Landlock_Files, Check__Landlock_Net, Check__Network_Namespace,
          Check__Cgroups, Check__Process_Count, Check__Write_Probe, Check__Openssl, Check__Doors)
MARK = {PASS: "ok", WARN: "warn", FAIL: "no", SKIP: "todo"}
VERDICT = {PASS: ("healthy", "a policy will hold here as written", "ok"),
           WARN: ("degraded", "a policy will hold here with the gaps named above", "warn"),
           FAIL: ("FAILED", "a policy cannot be enforced here; run refuses rather than pretend", "no")}
EXIT = {PASS: 0, WARN: 0, FAIL: 1}


class Doctor__Context:
    """What one check learns and the next needs."""
    abi = 0
    cgroup_writable = False


class CLI__Doctor:
    def __init__(self, main):
        self.main = main

    def run_checks(self) -> list:
        ctx = Doctor__Context()
        results = []
        stop = False
        for cls in CHECKS:
            if stop:
                results.append(Check__Result(cls.__name__.replace("Check__", "").lower(), SKIP, "skipped: an earlier check failed"))
                continue
            with self.main.trace.step(cls.__name__):
                res = cls().execute(ctx)
            results.append(res)
            if res.status == FAIL and res.fatal:
                stop = True
        return results

    @staticmethod
    def overall(results: list) -> str:
        statuses = {r.status for r in results}
        return FAIL if FAIL in statuses else WARN if WARN in statuses else PASS

    def cmd_doctor(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        results = self.run_checks()
        overall = self.overall(results)
        m.state.record("doctor", overall=overall)
        if m.json:
            print(json.dumps({"schema": "sharness-ai.doctor/v0", "overall": overall,
                              "checks": [r.as_dict() for r in results],
                              "at": time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime())}, indent=1))
            return EXIT[overall]
        lines = d.head("doctor", "can a policy hold here? nine checks, each with what to do about it")
        lines.append("")
        total = len(results)
        for i, r in enumerate(results, 1):
            mark = t.style(t.glyph(MARK[r.status]), MARK[r.status]) if MARK[r.status] != "warn" else t.style("!", "warn") if not t.unicode else t.style("⚠", "warn")
            ms = t.style(f"({r.duration_ms} ms)", "dim") if r.duration_ms else ""
            lines.append(f"  [{i}/{total}] {mark} {r.name:<18} {r.message}  {ms}".rstrip())
            if r.hint and r.status in (WARN, FAIL):
                lines += ["  " + x for x in d.box("what to do", d.kv("", r.hint, label_w=0, indent=0))]
        lines.append("")
        word, text, style = VERDICT[overall]
        lines += d.kv("overall", f"{word}: {text}", style=style)
        nxt = ("sharness-ai hello   the acceptance test, six probes under one policy" if overall != FAIL
               else "sharness-ai policy new   write a policy here; enforce it where there is a kernel")
        lines += d.kv("next", nxt, style="head")
        t.write(*lines)
        return EXIT[overall]
