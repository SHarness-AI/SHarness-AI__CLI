"""sharness.launcher, the first slice: `sharness-ai shell`. One session, one unique uid where the
launcher is root, the net door started for that uid, a shell under a policy that reaches nothing
but the proxy's port, HTTPS_PROXY pointing there, and a live page on loopback that shows the
traffic, the processes and the decisions as they happen. Status: runnable, proposed (26 Oct
2026). It is the launcher for one shell, not the launcher of the design: it starts no other door
under its own policy, checks no edge's contract by hash, and the doors run as the launcher's own
children. What it does make true: the shell's host allowlist is a Boundary for the shell, held by
sharness.net outside the shell's uid, and the kernel holds the port."""
from sharness_ai.launcher.Launcher import Launcher

__all__ = ["Launcher"]
