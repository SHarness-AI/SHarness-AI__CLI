# sharness-ai: a policy the kernel enforces, for every process an AI agent starts

[![PyPI](https://img.shields.io/pypi/v/sharness-ai)](https://pypi.org/project/sharness-ai/)
[![Python](https://img.shields.io/pypi/pyversions/sharness-ai)](https://pypi.org/project/sharness-ai/)
[![tests](https://github.com/SHarness-AI/SHarness-AI__CLI/actions/workflows/tests.yml/badge.svg?branch=dev)](https://github.com/SHarness-AI/SHarness-AI__CLI/actions/workflows/tests.yml)
[![Website](https://img.shields.io/badge/site-sharness.ai-0f766e)](https://sharness.ai)
[![Try it in your browser](https://img.shields.io/badge/try_it-in_your_browser-5b21b6)](https://sharness.ai/code/playground/index.html)

**SHarness** runs an agent's tools as small processes, each under a **Process Behaviour Policy**:
what it may read, write, run and connect to, named by one hash the person supplies and enforced
by the Linux kernel. A tricked agent cannot widen it, because the kernel was told before the
process started. Standard library only, Python 3.11+.

![The one idea: a policy is written, hashed to one name, and handed to the kernel before the agent's tool starts; reads and workspace writes are allowed, a connect to port 80 and a 200 MiB allocation are refused](docs/anim/one-idea.svg)

## Try it in 60 seconds

**In your browser, nothing installed:** [the playground](https://sharness.ai/code/playground/index.html)
puts `pip install sharness-ai` in Pyodide next to a shell on a real Linux kernel with Landlock, booted
in the tab, where every `sharness-ai run` is enforced. Or just [watch the kernel boot](https://sharness.ai/code/browser/demo/index.html).

**On Linux (5.13 or later):**

```bash
pip install git+https://github.com/SHarness-AI/SHarness-AI__CLI@dev
sharness-ai probe                                   # what a process here can do before any policy
sharness-ai hello                                   # the acceptance test: six probes, six held
sharness-ai run --policy experiments/policies/p2-tool-server.json -- my-tool   # any command, under a policy
```

![sharness-ai hello replayed: read allowed; two writes, a connect, a 400 MiB allocation and a wrong hash refused; result 6 of 6 held; then the caveat](docs/anim/hello-replay.svg)

**Then tell us what it said.** `sharness-ai hello --json` and
[a two-field report](https://github.com/SHarness-AI/SHarness-AI__CLI/issues/new?template=hello-report.yml):
every machine becomes a row on [sharness.ai/evidence/machines](https://sharness.ai/evidence/machines/index.html),
and a refusal that did not happen is the most useful thing you can send.

> **Status: experiments.** No SHarness component (launcher, kms, net, fs, bash, llm) is built. This
> package carries the experiments: `probe`, `policy hash|check|translate`, `run`, `hello`, and a
> browser bench where the same guest kernel runs in Node, in a tab and through chroot. The release
> on PyPI (v0.1.0) is the skeleton; the commands are on `dev`, the default branch, and ship with the
> next release from `main`. The design is published for review at [sharness.ai](https://sharness.ai).

## What is enforced, by what, and the caveat

| In the policy | Enforced by | Measured |
|---|---|---|
| `files.read`, `files.write`, `files.exec` (path prefixes) | Landlock path rules, applied in the child before `execve` | writes refused, reads allowed, in five places |
| `network: {"connect_tcp_ports": [443]}` | Landlock TCP port rules (ABI 4+, Linux 6.7+) | port 80 `EACCES`, port 443 allowed |
| `network: "none"` | an empty network namespace where the process may make one, else Landlock denying every TCP bind and connect | the connect refused |
| `process.max_memory_mb`, `process.max_pids` | `RLIMIT_AS` and `RLIMIT_NPROC`, plus a memory and pids cgroup where `/sys/fs/cgroup` is writable | 400 MiB under 128 MiB raises `MemoryError`; the fifth fork under `max_pids: 4` fails |
| `process.no_new_privs` | `prctl(PR_SET_NO_NEW_PRIVS)` | set before every run |
| the hash | `--expect-hash sha256:…` refuses to run anything else, exit 125 | a wrong hash runs nothing |

Not here yet: seccomp, per-component uids, mutual TLS, hostnames (ports only), UDP (Landlock does not
see it, so without the namespace DNS still resolves), the launcher, any component.

**The caveat is part of every result.** A policy a process applies to its own children is a
Boundary for them and only a Setting for itself: it could have skipped it. Making it a Boundary for
the agent too needs the launcher above the agent, which is the design, not yet code:
[who enforces decides](https://sharness.ai/design/policies/index.html#2-who-enforces-decides-the-barrier-kind).

## A real Linux kernel, in a browser tab

![A browser tab opens sharness.ai, v86 starts, Linux 6.18 boots and prints landlock: Up and running, hello holds 6 of 6 at 28.5 seconds, and the example policies refuse a write, a port and an allocation](docs/anim/kernel-in-a-tab.svg)

`experiments/browser/` builds one Alpine x86 guest (Alpine's `linux-virt` kernel, Landlock on, Python
3.12, this package, the example policies) with the standard library, and runs it three ways:
`npm run node` (v86 in Node, no browser), `npm run browser` (the page in headless Chromium) and
`sudo npm run native` (the same i386 binaries through chroot on the host kernel). `hello` held 6 of 6
in all three on 25 Oct 2026. The story, with screenshots: [Linux in a tab](https://sharness.ai/articles/linux-in-a-tab.html).

## Example policies

Seven in [experiments/policies/](experiments/policies/README.md): two minimal examples and five
profiles with `/work` as the workspace, from P0 (a hello world, 64 MiB, 8 processes) through P1 (a
coding agent's session), P2 (a tool or MCP server on stdio, read-only, no network), P3 (the sgit.ai
newsroom agent) to P4 (the sgit CLI). Each hashes to the same value in Python, in the browser and
in the Linux guest. One policy, written once, can also be written for another enforcer:

```bash
sharness-ai policy translate experiments/policies/p1-agent-session.json --to claude-code   # or bwrap, docker, kubernetes
```

prints the target's form and then, line by line, what that target does **not** enforce: the
[enforceability matrix](https://sharness.ai/landscape/enforceability/index.html), made executable.

SHarness is unrelated to Sharness, the shell testing library.

## The commands: the first experiments

Numbered and described in [experiments/README.md](experiments/README.md); the map of mockups,
experiments and storyboards is [sharness.ai/code/experiments](https://sharness.ai/code/experiments/index.html).

| Command | Experiment | What it shows |
|---|---|---|
| `sharness-ai probe` | E01 | the **grant**: what a process here can do before any policy (uid, capabilities, Landlock ABI, `memfd_secret`, namespaces, tools, whether egress is proxied). Read-only; prints the names of proxy variables, never values |
| `sharness-ai policy hash FILE` | E02 | the one value the person supplies: canonical JSON → `sha256:…`. The [browser mockup](https://sharness.ai/explain/mockups/policy-hash.html) produces the same hash from the same file |
| `sharness-ai policy check FILE` | E02 | the shape of a v0 Process Behaviour Policy |
| `sharness-ai policy translate FILE --to bwrap\|docker\|claude-code\|kubernetes\|landlock [-- CMD…]` | E10 | the same policy in another enforcer's form (a bubblewrap or `docker run` command line, a Claude Code sandbox `settings.json` fragment, a Kubernetes Pod and NetworkPolicy), followed by the list of what that target does **not** enforce: the [enforceability matrix](https://sharness.ai/landscape/enforceability/index.html), row by row |
| `sharness-ai run --policy FILE [--expect-hash sha256:…] -- CMD…` | E03 | one command under a policy: Landlock file and exec rules, TCP port rules, no network, a memory cap and a process-count cap (`RLIMIT_AS`, `RLIMIT_NPROC`, and a cgroup where one can be made); refuses to run anything if the hash does not match |
| [the playground](https://sharness.ai/code/playground/index.html), or `experiments/browser/playground.html` | E09 | type `sharness-ai` into Pyodide (`pip install`, then hash, check, translate; `run` and `hello` refuse with no kernel) and into a shell on the Linux guest (everything, enforced); one policy hashed three ways |
| `experiments/browser/`: `npm run node`, `npm run browser`, `sudo npm run native` | E09 | the same `hello` and `run` under a second kernel: Alpine x86 with Landlock booted by v86 in Node and in a browser tab, and the same binaries through chroot on the host kernel |
| `sharness-ai hello` | E04 | the memo's acceptance test for one child process: read allowed, writes refused, network refused, a 400 MiB allocation under a 128 MiB cap refused, wrong hash refused. Exit 0 when every expectation held |

```
$ sharness-ai hello
sharness-ai hello   experiment E04: the memo's acceptance test, for one child process
policy      hello  sha256:…
  ✔ read       expected allowed  got allowed
  ✔ write-tmp  expected refused  got refused (PermissionError: [Errno 13] Permission denied: '/tmp/sharness-ai-hello.tmp')
  ✔ write-cwd  expected refused  got refused (PermissionError: [Errno 13] Permission denied: 'sharness-ai-hello.tmp')
  ✔ net        expected refused  got refused (PermissionError: [Errno 13] Permission denied)
  ✔ memory     expected refused  got refused (MemoryError)
  ✔ hash       expected refused  got refused
result      6/6 held
caveat      applied by this process to its own children: a Boundary for them, a Setting for whoever ran this ...
```

**What is enforced, and by what.** Files and exec by [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
path rules (Linux 5.13+, through `ctypes`, no C extension); TCP by Landlock port rules (ABI 4+,
Linux 6.7+); `network: "none"` also tries an empty network namespace. Landlock does not see UDP,
so without the namespace DNS still resolves. `process.max_memory_mb` and `max_pids` set `RLIMIT_AS`
and `RLIMIT_NPROC` on the child and, where `/sys/fs/cgroup` is writable, a memory and pids cgroup
(measured 25 Oct 2026: a 400 MiB allocation under 128 MiB raises MemoryError; the fifth fork under
`max_pids: 4` fails). Not here yet: seccomp, per-component uids, mutual TLS, the launcher, any component. Standard library only; Python 3.11+.

**The caveat is part of the result.** A policy a process applies to its own children is a Boundary
for them and only a Setting for itself (it could have skipped it). Making it a Boundary for the
agent too needs the launcher above the agent: [who enforces decides](https://sharness.ai/design/policies/index.html#2-who-enforces-decides-the-barrier-kind).

**For a Claude Code session:** the skill in [.claude/skills/sharness-hello](.claude/skills/sharness-hello/SKILL.md)
runs E01 and E04 inside the session under the design's safety rules and reports the result in the
site's status words.

## Releases

Every push to `main` runs `.github/workflows/workflow.yml`: unit tests, then a version bump
(`v0.N.0` → `v0.N+1.0`, written to `pyproject.toml`, `sharness_ai/version` and the badge above),
a git tag, and a publish to PyPI via Trusted Publishing (OIDC — no API token is stored).
Day-to-day work lands on `dev` (the default branch); merging `dev` into `main` cuts a release.
