# decide: a command, a policy, an intent, and one of three answers (prototype, not an experiment yet)

Work in progress on a branch, by pbp@sharness, 26 Oct 2026, for cli@sharness to take or replace
(board row T23). Not part of the package; no tests yet; the design is on
https://sharness.ai/design/decision/.

    python3 -I decide.py ../policies/p1-agent-session.json /work samples.json

Given a shell command, the policy the process runs under, the working directory and the agent's
stated intent, it answers **allow**, **deny** or **ask**, with a one-line summary in the shape
ux.sgit.ai's UX-059 asks a permission prompt to have (reads, writes, network, reversible) and, for
**ask**, a question in the person's words. Unknown commands are refused: what cannot be read
cannot be allowed. The last dictionary of each verdict is the PreToolUse hook output Claude Code
reads, so the same function can sit behind a hook today.

What it is in ABP terms: a **Setting** wherever the process that asks is the one that would run
the command (a hook in the agent's own process); a **Boundary** only when it answers inside
`sharness.bash`, a separate process, with the kernel rows closing the side doors. A parser is not a
sandbox: whatever this engine misses, the kernel refuses or does not, by the policy's rows, and
that is the whole of the protection. 99 lines, standard library only.
