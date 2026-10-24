# sharness-ai — the SHarness CLI

[![PyPI](https://img.shields.io/pypi/v/sharness-ai)](https://pypi.org/project/sharness-ai/)
[![Python](https://img.shields.io/pypi/pyversions/sharness-ai)](https://pypi.org/project/sharness-ai/)
![Current Release](https://img.shields.io/badge/release-v0.1.0-blue)
[![Website](https://img.shields.io/badge/site-sharness.ai-0f766e)](https://sharness.ai)

**📖 Website: [sharness.ai](https://sharness.ai)** — the design, the evidence behind it, and the
open decisions. **🤖 Reading this as an AI agent?** [sharness.ai/llms.txt](https://sharness.ai/llms.txt)
is the index; every design page is also available as markdown at the same path (`…/index.md`).

> **Status: design.** Nothing described below is built yet. This package is the skeleton and
> the release pipeline; the design is published for review at sharness.ai.

## What SHarness is (proposed scope)

SHarness runs agents and their tools as small, single-purpose processes, each locked down by
the kernel and talking only over allowed, mutually authenticated connections, so a secret lives
in one place and a tricked process can only do its one job.

It started as a fix for one gap: a vault key handed to an AI agent was sealed while it travelled
and exposed the moment it arrived — on disk, on the command line and in the agent's transcript.
The fix turned out to be general. A launcher starts a few components, each under its own
Process Behaviour Policy, enforced by Linux (separate users, Landlock, seccomp, namespaces,
cgroups) and by mutual TLS between components. The person supplies the hash of the policy, so a
prompt-injected agent cannot widen it. sgit ([sgit.ai](https://sgit.ai)'s encrypted vault CLI)
is the first app designed to run inside it.

| Component | Its one job (designed) |
|---|---|
| `sharness.launcher` | verifies the policy hash; makes uids, a session CA and certificates; starts, freezes and stops components |
| `sharness.kms` | holds private keys and secrets; opens sealed things; re-seals to one-time keys — never returns a clear key |
| `sharness.net` | the only network client; host, endpoint and id allowlists |
| `sharness.fs` | the only writer of protected folders |
| `sharness.bash` | runs shell commands, each in a fresh sandbox, under a profile |
| `sharness.llm` | the only client of the model API; secret filter on tool results |
| `sharness.policy` | the policy manifest, its layers and its hash (not a process) |

Read more on the site:
[why](https://sharness.ai/why/index.html) ·
[architecture](https://sharness.ai/architecture/index.html) ·
[components](https://sharness.ai/components/index.html) ·
[keys and the KMS](https://sharness.ai/keys/index.html) ·
[Process Behaviour Policies](https://sharness.ai/policies/index.html) ·
[agents and LLMs](https://sharness.ai/agents/index.html) ·
[evidence](https://sharness.ai/evidence/index.html) ·
[roadmap and open decisions](https://sharness.ai/roadmap/index.html) ·
[the source design documents](https://sharness.ai/documents/index.html)

SHarness is unrelated to Sharness, the shell testing library.

## Install

```bash
pip install sharness-ai
sharness-ai --version
```

Today the package only reports its version and prints its help.

The command is `sharness-ai`, the same name as the PyPI distribution. There is deliberately
no plain `sharness` command: that is the Debian / pkgsrc / OpenBSD package name of the unrelated
shell test library (v0.1.0 shipped a `sharness` shorthand; it is removed from the next release).
Proposed environment variable prefix: `SHARNESS_AI_` (not `SHARNESS_`, which the shell test
library uses).

## Releases

Every push to `main` runs `.github/workflows/workflow.yml`: unit tests, then a version bump
(`v0.N.0` → `v0.N+1.0`, written to `pyproject.toml`, `sharness_ai/version` and the badge above),
a git tag, and a publish to PyPI via Trusted Publishing (OIDC — no API token is stored).
Day-to-day work lands on `dev` (the default branch); merging `dev` into `main` cuts a release.
