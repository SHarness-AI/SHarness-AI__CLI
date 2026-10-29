"""`sharness-ai shell`: an interactive shell under the harness, with the live page."""
import json
import os
import sys

from sharness_ai.launcher import Launcher
from sharness_ai.launcher.Launcher import LaunchError


class CLI__Shell:
    def __init__(self, main):
        self.main = main

    def cmd_shell(self, args) -> int:
        m = self.main
        t, d = m.term, m.draw
        argv = args.argv[1:] if args.argv[:1] == ["--"] else list(args.argv)
        argv = argv or [os.environ.get("SHELL") if os.path.exists(os.environ.get("SHELL", "")) else "/bin/sh"]
        unique = None if args.user is None else args.user
        launcher = Launcher(args.workspace, args.sites or [], profile=args.profile, agent=args.agent or "shell", unique_uid=unique,
                            memory_mb=args.memory_mb, pids=args.pids, ui=not args.no_ui, keep_user=args.keep_user)
        try:
            info = launcher.start()
        except (LaunchError, Exception) as e:  # noqa: BLE001 - one place, one sentence
            launcher.stop()
            return m.fail(str(e), hint="sharness-ai doctor says what this machine has; --no-user runs the shell as this uid", code=2)
        sep = f" {t.glyph('dot')} "
        if m.json:
            print(json.dumps({k: v for k, v in info.items() if k != "v0"}, indent=1), file=sys.stderr)
        else:
            lines = d.head("shell", "a shell under the harness: the kernel holds the files and one port, sharness.net holds the hosts")
            lines += d.kv("you said", launcher.chain.top.notes[0], style="bold")
            lines += d.kv("the name", f"{info['sentence_hash']}  (the shell's policy {d.hash_short(info['policy_hash'])})", style="accent")
            who = f"uid {info['uid']}" + (f" ({info['user']}, made for this shell, removed on exit)" if info["user"] else " (this uid: a Setting)")
            lines += d.kv("who", who)
            lines += d.kv("network", f"only 127.0.0.1:{info['proxy_port']}, sharness.net.proxy{sep}hosts {' '.join(args.sites or []) or 'none'}{sep}HTTPS_PROXY set")
            lines += d.kv("held", f"{t.mark('ok')} files, the port and the caps by the kernel{sep}{t.mark('ok')} the host names by sharness.net (a Boundary for the shell: another uid, outside it)" if info["user"]
                          else f"{t.mark('ok')} files, the port and the caps by the kernel{sep}the host names by sharness.net (same uid: a Setting)", style="ok")
            lines += d.kv("not covered", "Unix sockets by path, kernel refusals on the page; the namespace has loopback only, so a program that resolves names itself finds no DNS", style="dim")
            if info["ui"]:
                lines += d.kv("live page", info["ui"], style="head")
            lines += d.kv("exit", "leave the shell and the session, the doors and the user are removed", style="dim")
            lines.append(d.rule(f"{os.path.basename(argv[0])} starts"))
            t.write(*lines)
        try:
            code = launcher.run_shell(argv, info["proxy_port"])
        finally:
            summary = launcher.stop()
        if not m.json:
            t.write(d.rule(f"{os.path.basename(argv[0])} exit {code}"))
            t.write(*d.kv("summary", f"{summary['requests']} requests through sharness.net: {summary['allowed']} allowed, {summary['refused']} refused"
                                     + (f"; hosts reached: {' '.join(summary['hosts'])}" if summary["hosts"] else ""), style="bold"))
            if summary["cleanup"]:
                t.write(*d.kv("not undone", summary["cleanup"], style="warn"))
        else:
            print(json.dumps({"exit": code, **summary}), file=sys.stderr)
        return code
