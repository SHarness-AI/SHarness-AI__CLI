"""sharness-ai: the SHarness command line tool (https://sharness.ai).

Status: experiments. Nothing here is a SHarness component. The commands are the first
experiments from the design, drawn as screens that say where you are and what to do next
(sharness.ai/articles/the-cli-is-the-front-door.html):

    (no arguments)                  the guide: where you are, the ladder, a menu (a terminal)
    probe                      E01  the grant: what a process here can do before any policy
    policy hash|check|show FILE E02 the one value the person supplies: canonical JSON → sha256
    policy new [FILE]               five questions write a policy; policy edit changes one edge
    policy translate FILE --to T    E10  the same policy as bwrap, docker, claude-code, kubernetes; and the gap
    run --policy FILE -- CMD   E03  one command under a policy: the plan, then the command
    hello                      E04  the acceptance test, six probes under one policy, as a scoreboard
    components [NAME]               the operating system a process sees: designed, not built
"""
from sharness_ai.cli.CLI__Main import CLI__Main, build_parser, main

__all__ = ["CLI__Main", "build_parser", "main"]
