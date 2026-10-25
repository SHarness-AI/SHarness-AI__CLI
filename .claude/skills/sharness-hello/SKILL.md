---
name: sharness-hello
description: Run the SHarness experiments E01 (probe the grant) and E04 (the hello-world acceptance test) inside the current Claude Code session, following the safety rules for testing in a live agent session, and report the result in the site's status words (measured, with date and environment). Use when asked to "run the sharness hello", "probe this environment for SHarness", "measure the grant", or to check whether a policy would hold here.
---

# sharness-hello

You are about to run two experiments from https://sharness.ai/code/experiments/index.html in this
session. They are small, read-only or confined to child processes, and they are the first two
rungs of the SHarness ladder: nothing here is a SHarness component.

## Safety rules (from https://sharness.ai/design/process-tree/index.html#4-safety-rules-for-testing-inside-a-live-agent-session)

1. Never touch the orchestrator (the Claude Code process) or the session bridge.
2. Never add firewall rules, never change sysctls, never create users for this.
3. Everything runs as a **child subtree** that ends when the command ends. `sharness-ai run`
   and `sharness-ai hello` fork a child, apply the policy to the child, and exit. They never
   restrict the shell you run them from.
4. Leave nothing behind. `hello` writes only a temporary policy file and deletes it.

## Steps

1. Install from PyPI, or from the repository checkout if that is where you are:
   `pip install sharness-ai` (or `pip install -e .`). Check: `sharness-ai --version`.
   If the installed release does not have the `probe` and `hello` commands yet, install from
   the repository: `pip install git+https://github.com/SHarness-AI/SHarness-AI__CLI@dev`.
2. `sharness-ai probe` and `sharness-ai probe --json`. This is E01: the grant. It prints the
   names of proxy variables only, never values. Do not add values yourself.
3. `sharness-ai hello` and `sharness-ai hello --json`. This is E04. Exit 0 means every
   expectation held. If the kernel has no Landlock, it says so and nothing is enforced.
4. Report, in this order and with these words:
   - **Environment:** OS and kernel, Landlock ABI, uid, Python version (from probe).
   - **Measured, as of <today's date>:** the `hello` result table and the policy hash.
   - **The caveat, verbatim from the output.** A policy applied by this session to its own
     child is a Boundary for the child and only a Setting for the session.
   - What was **not** measured: seccomp, uids, cgroups, mutual TLS, the process tree.
5. If asked to publish: the JSON belongs on the Evidence page of the site with method and
   date (https://sharness.ai/evidence/index.html), not in a chat message alone.

## Never

- Never present `hello` passing as "the agent is sandboxed". It shows one child process
  under one policy. Say so.
- Never write a policy that includes a secret, and never print the value of an environment
  variable that may hold one.
