# The release checklist: run on every release, from PyPI, in a fresh environment

The version under test is the one on [pypi.org/project/sharness-ai](https://pypi.org/project/sharness-ai/).
Start from a fresh environment (a new VM, container or venv), install from PyPI and never from this
repository. Answer each row as [`README.md`](README.md) says. Personas: **N** newcomer, **B** builder,
**S** skeptic.

| Id | Who | Do | Expect |
|---|---|---|---|
| R1 | N | Read the PyPI page top to bottom, then `pip install sharness-ai` | It installs with no dependencies pulled in. The page says what the tool is, what exists and what does not, in under a minute of reading |
| R2 | N | `sharness-ai --version` | The version PyPI shows |
| R3 | N | `sharness-ai` with no arguments | A screen that says where you are, what to do next and the command to type. No traceback |
| R4 | N | `sharness-ai probe`, then `sharness-ai probe --json` | Every row is a fact of your machine or says why it does not apply. The JSON parses |
| R5 | N | `sharness-ai doctor` | An overall verdict and a next step |
| R6 | N | `sharness-ai hello` | On Linux 5.13 or later, 6 of 6 held. Elsewhere, one line saying why it refuses, and nothing runs |
| R7 | N | `sharness-ai policy new my-tool.json`, answering the five questions, then `sharness-ai run --policy my-tool.json -- ls` | A policy file, its hash, and `ls` running under it (Linux) |
| R8 | B | `sharness-ai run --policy my-tool.json -- sh -c 'echo x > /etc/sharness-test'` | Refused, and the message says who refused (the kernel) and which row to change |
| R9 | B | `sharness-ai contain --workspace . --sites pypi.org --dry-run -- my-agent` | The sentence read back, one hash, what is held, what is not held yet, what is never covered |
| R10 | B | `sharness-ai policy translate my-tool.json --to docker` (and `bwrap`, `claude-code`, `kubernetes`) | A command line for each, and a list of what that target cannot enforce |
| R11 | S | Read every screen above for its claims | Nothing claims protection against root or the kernel. Where a policy is applied by a process to its own child, the screen says Boundary for the child and Setting for the parent. UDP, Unix sockets by path and the inherited environment are named as not covered |
| R12 | S | Pick any refusal above and try to get around it without root | Report what you tried, whether it held, and who refused |
| R13 | N | Look at the PyPI page in a browser | Every figure shows and every link opens (the README is the page; a relative path breaks there) |
| R14 | all | Anything else a user would do in their first ten minutes | A *Confusing* is as useful as a *Not confirmed* |
