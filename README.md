# sharness-ai — the SHarness CLI

[![PyPI](https://img.shields.io/pypi/v/sharness-ai)](https://pypi.org/project/sharness-ai/)
[![Python](https://img.shields.io/pypi/pyversions/sharness-ai)](https://pypi.org/project/sharness-ai/)
![Current Release](https://img.shields.io/badge/release-v0.1.0-blue)
[![Website](https://img.shields.io/badge/site-sharness.ai-0f766e)](https://sharness.ai)

**📖 Website: [sharness.ai](https://sharness.ai)** — the design, the evidence behind it, and the
open decisions. **🤖 Reading this as an AI agent?** [sharness.ai/llms.txt](https://sharness.ai/llms.txt)
is the index; every design page is also available as markdown at the same path (`…/index.md`).

> **Status: experiments.** No SHarness component is built. This package carries the first
> experiments from the design (`probe`, `policy hash`, `run`, `hello`), each small enough to read
> in one sitting, and the release pipeline. The design is published for review at sharness.ai.

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

The release on PyPI (v0.1.0, as of 24 Oct 2026) only reports its version. The commands below are on
`dev` and ship with the next release from `main`; until then: `pip install git+https://github.com/SHarness-AI/SHarness-AI__CLI@dev`.

## The commands: the first experiments

Numbered and described in [experiments/README.md](experiments/README.md); the map of mockups,
experiments and storyboards is [sharness.ai/experiments](https://sharness.ai/experiments/index.html).

| Command | Experiment | What it shows |
|---|---|---|
| `sharness-ai probe` | E01 | the **grant**: what a process here can do before any policy (uid, capabilities, Landlock ABI, `memfd_secret`, namespaces, tools, whether egress is proxied). Read-only; prints the names of proxy variables, never values |
| `sharness-ai policy hash FILE` | E02 | the one value the person supplies: canonical JSON → `sha256:…`. The [browser mockup](https://sharness.ai/mockups/policy-hash.html) produces the same hash from the same file |
| `sharness-ai policy check FILE` | E02 | the shape of a v0 Process Behaviour Policy |
| `sharness-ai run --policy FILE [--expect-hash sha256:…] -- CMD…` | E03 | one command under a policy: Landlock file and exec rules, TCP port rules, no network; refuses to run anything if the hash does not match |
| `sharness-ai hello` | E04 | the memo's acceptance test for one child process: read allowed, write refused, network refused, wrong hash refused. Exit 0 when every expectation held |

```
$ sharness-ai hello
sharness-ai hello   experiment E04: the memo's acceptance test, for one child process
policy      hello  sha256:…
  ✔ read       expected allowed  got allowed
  ✔ write-tmp  expected refused  got refused (PermissionError: [Errno 13] Permission denied: '/tmp/sharness-ai-hello.tmp')
  ✔ write-cwd  expected refused  got refused (PermissionError: [Errno 13] Permission denied: 'sharness-ai-hello.tmp')
  ✔ net        expected refused  got refused (PermissionError: [Errno 13] Permission denied)
  ✔ hash       expected refused  got refused
result      5/5 held
caveat      applied by this process to its own children: a Boundary for them, a Setting for whoever ran this ...
```

**What is enforced, and by what.** Files and exec by [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
path rules (Linux 5.13+, through `ctypes`, no C extension); TCP by Landlock port rules (ABI 4+,
Linux 6.7+); `network: "none"` also tries an empty network namespace. Landlock does not see UDP,
so without the namespace DNS still resolves. Not here yet: seccomp, per-component uids, cgroups,
mutual TLS, the launcher, any component. Standard library only; Python 3.11+.

**The caveat is part of the result.** A policy a process applies to its own children is a Boundary
for them and only a Setting for itself (it could have skipped it). Making it a Boundary for the
agent too needs the launcher above the agent: [who enforces decides](https://sharness.ai/policies/index.html#2-who-enforces-decides-the-barrier-kind).

**For a Claude Code session:** the skill in [.claude/skills/sharness-hello](.claude/skills/sharness-hello/SKILL.md)
runs E01 and E04 inside the session under the design's safety rules and reports the result in the
site's status words.

## Releases

Every push to `main` runs `.github/workflows/workflow.yml`: unit tests, then a version bump
(`v0.N.0` → `v0.N+1.0`, written to `pyproject.toml`, `sharness_ai/version` and the badge above),
a git tag, and a publish to PyPI via Trusted Publishing (OIDC — no API token is stored).
Day-to-day work lands on `dev` (the default branch); merging `dev` into `main` cuts a release.
