# Experiments

The memo of 24 October 2026 asks for SHarness to start with *very simple examples, each
component done in isolation, as slim as possible, then harden, then test*. This folder is the
ladder: numbered experiments, each small enough to read in one sitting, each saying where it
runs and what it does and does not show. The map, with the browser mockups and the storyboards,
is on [sharness.ai/code/experiments](https://sharness.ai/code/experiments/index.html).

Status words, as on the site: **runnable** means the code is in this repository and its tests
pass; **measured** means run in a named environment on a named date; **planned** means described
only. No experiment is a SHarness component.

| # | Experiment | Runs where | Status |
|---|---|---|---|
| E01 | `sharness-ai probe`: the grant, what a process here can do before any policy | any OS (Linux for the kernel facts) | runnable |
| E02 | `sharness-ai policy hash`: canonical JSON → `sha256:…`, the one value the person supplies; the same hash in the [browser mockup](https://sharness.ai/explain/mockups/policy-hash.html) | any OS, and the browser | runnable |
| E03 | `sharness-ai run --policy p.json -- cmd`: one command under a policy (Landlock files and TCP ports, no network; memory and process-count caps by rlimit and cgroup) | Linux 5.13+ (Landlock ABI 1; TCP rules ABI 4; cgroups need root or a delegated subtree) | runnable, caps measured 25 Oct 2026 |
| E04 | `sharness-ai hello`: the memo's acceptance test for one child process: read allowed, writes refused, network refused, memory over the cap refused, wrong hash refused | Linux; a Claude Code session via the [skill](../.claude/skills/sharness-hello/SKILL.md) | runnable, measured 24 and 25 Oct 2026 (6 of 6) |
| E05 | session CA + role certificates + the edge matrix over mutual TLS (what the design measured by hand) as a repeatable script | any OS with `cryptography` | planned |
| E06 | the process-tree proof of concept: a mini orchestrator that cannot exec a shell, and a bash server outside its domain | Linux, root, following the [safety rules](https://sharness.ai/design/process-tree/index.html#4-safety-rules-for-testing-inside-a-live-agent-session) | planned |
| E07 | `sharness.llm` as a Messages API pass-through with a secret filter on tool results, pointed at by `ANTHROPIC_BASE_URL` | any OS | planned |
| E08 | `sharness.kms` v0: make an identity in-process, open a sealed `m1`, re-seal derived keys to a one-time key, never print a clear key | any OS with `cryptography` | planned |
| E09 | the harness under a second kernel: Alpine 3.23 x86 with Alpine's `linux-virt` (Landlock on) booted by v86 in Node and in a browser tab, running `probe`, `hello`, `run` and the example policies; the same i386 rootfs run through chroot on the host kernel ([browser/](browser/README.md)) | Node 18+; any browser; Linux root for the chroot form | runnable, measured 25 Oct 2026 (6 of 6 in all three forms) |
| E10 | `sharness-ai policy translate FILE --to bwrap\|docker\|claude-code\|kubernetes`: the same policy in another enforcer's form, with the list of what that target does not enforce | any OS (writes the form; does not run the target) | runnable; targets not run here |

## E01 probe

```
$ sharness-ai probe
sharness-ai probe   the grant: what a process here can do before any policy
identity    uid 0 (root) · capabilities all (CapEff 000001fffeffffff, ...) · NoNewPrivs 0 · Seccomp 0
kernel      linux 6.18.44 · Landlock ABI 7 · memfd_secret yes · cgroups hybrid (v1 + unified)
...
reading     this process is root with every capability and no seccomp: the grant is everything.
```

Read-only. Prints the *names* of proxy variables, never their values. `--json` for machines.
The reading line is the ABP delta in one sentence: grant minus mandate, before any policy.

## E02 policy hash

A v0 Process Behaviour Policy is a small JSON object ([policies/](policies/)). Its hash is
SHA-256 over canonical JSON: sorted keys, no whitespace, UTF-8, integers only. Floats are
refused rather than canonicalised, so Python and the browser produce identical bytes:

```
$ sharness-ai policy hash experiments/policies/deny-all-example.json
sha256:ab1d3e4e779313274f7a1d3ef3e46f6eacef038d8cfaa6198151a45cd82dcc76
```

Paste the same file into [the browser mockup](https://sharness.ai/explain/mockups/policy-hash.html)
and the hash must be the same. That is the whole experiment: two implementations, one hash,
so a person can supply it from outside the agent and a launcher can check it.

## E03 run

```
$ sharness-ai run --policy experiments/policies/deny-all-example.json -- /bin/sh -c 'touch /x'
touch: cannot touch '/x': Permission denied
$ sharness-ai run --policy experiments/policies/allow-https-example.json -- python3 -I -c \
    "import socket; socket.create_connection(('1.1.1.1', 443))"        # allowed: port 443
$ sharness-ai run --policy experiments/policies/allow-https-example.json -- python3 -I -c \
    "import socket; socket.create_connection(('1.1.1.1', 80))"         # PermissionError
```

The child gets `SHARNESS_AI_POLICY_HASH` and `SHARNESS_AI_POLICY_ID` in its environment, so a
harnessed app can say which policy it ran under. `--expect-hash sha256:…` refuses to run
anything unless the file hashes to that value: the launcher's first check, in one flag.

What it enforces, and with what: files and exec by Landlock path rules; TCP by Landlock port
rules (ABI 4+); `network: "none"` additionally tries an empty network namespace (root, or an
unprivileged user namespace where the kernel allows one). Landlock does not see UDP, so without
the namespace DNS still resolves. `process.max_memory_mb` and `process.max_pids`: `RLIMIT_AS` and
`RLIMIT_NPROC` on the child, plus a memory and pids cgroup (v1 or v2) where `/sys/fs/cgroup` is
writable; the parent removes the cgroup afterwards. seccomp, uids and mutual TLS are not here yet.

## E04 hello

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

Exit 0 when every expectation held. `--json` for publishing the result on the Evidence page.
The caveat is part of the result and is why it says *for one child process*: the memo's test
is passed for the agent itself only when a launcher above the agent applies the policy.

## E09 the harness under a second kernel

```
$ cd experiments/browser && npm ci && python3 build_guest.py
$ npm run node          # v86 in Node: the guest's serial console, exit 0 when hello held
$ npm run browser       # the same page in headless Chromium through Playwright
$ sudo npm run native   # the guest's i386 binaries on the host kernel through chroot
```

One guest (Alpine 3.23 x86, `linux-virt` 6.18 with `CONFIG_SECURITY_LANDLOCK=y`, Python 3.12,
this package, the example policies), three kernels to run it on: v86's emulated CPU in Node, the
same in a browser tab, and the host's kernel through the i386 syscall table. Every form applies
a policy to a child: a Boundary for the child, a Setting for the process that ran it. The build
script is standard library only and writes the initramfs itself; v86 is the one dependency, pinned,
and only under `experiments/browser/`. The same folder carries a playground: `sharness-ai` typed into Pyodide (hash, check, translate;
`run` and `hello` refuse, as they must with no kernel) and into a shell in the guest (everything,
enforced), with the guest on a network the page provides (its packets become the browser's `fetch()`)
and an interceptor that decodes every frame and vetoes hosts outside an egress allowlist, so a
kernel refusal (nothing leaves the process) and a page refusal (a 403 before any fetch) can be told apart. Details and the measured table: [browser/README.md](browser/README.md);
the options not taken and what a browser never shows: [sharness.ai/code/browser](https://sharness.ai/code/browser/index.html).

## E10 policy translate

```
$ sharness-ai policy translate experiments/policies/deny-all-example.json --to claude-code
{
  "sandbox": {
    "enabled": true,
    "allowUnsandboxedCommands": false,
    "failIfUnavailable": true,
    "filesystem": {"allowWrite": []},
    "network": {"allowedDomains": [], "strictAllowlist": true}
  }
}

# claude-code: not enforced from policy deny-all-example (sha256:ab1d3e4e7793…):
#   - files.read: not an allowlist in the sandbox; it reads most of the machine unless paths are listed in filesystem.denyRead ...
#   - files.exec: no equivalent; the sandbox has no execute allowlist
#   - covers Bash, PowerShell and Monitor commands and their children only; ...
#   - network none: expressed as an empty allowedDomains with strictAllowlist; ...
#   - the policy hash: settings are read by the agent's own process (a Setting in ABP terms); ...
```

The policy is the centre; every enforcer is a target. The notes are the gap, which is the
[enforceability matrix](https://sharness.ai/landscape/enforceability/index.html) made executable.
Nothing is run against the target: `translate` writes the form, `run` enforces ours.

## The example policies

[policies/](policies/README.md): two minimal examples and five profiles with `/work` as the
workspace, P0 a hello world (the caps), P1 a coding agent's session (writes the workspace and
`/tmp`, port 443), P2 a tool or MCP server on stdio (read-only, no network), P3 the sgit.ai
newsroom agent (a vault checkout in, articles out), P4 the sgit CLI (writes the vault checkout).
Run natively on 25 Oct 2026 against a stand-in workspace: P0 refused a 200 MiB allocation under
its 64 MiB cap; P1 connected on 443, was refused on 80, wrote the workspace; P2 was refused every
write and the connect; P3 wrote `out/` and was refused `vault/`; P4 ran `sgit 0.24.0 --version`
and `pki list`, wrote `vault/`, was refused `out/`, connected on 443, and saw its own hash in
`SHARNESS_AI_POLICY_HASH`. The same files hash and check identically in the E09 guest.

## Measured so far

| Date | Environment | Result |
|---|---|---|
| 24 Oct 2026 | one Claude Code cloud session (Ubuntu 24.04, Linux 6.18, Landlock ABI 7, uid 0, Python 3.13) | E04: 5/5 held; E03: port 443 allowed and port 80 refused under `allow-https-example`; whole `hello` run 0.6 s |
| 25 Oct 2026 | the same kind of session (cgroups v1 with a unified mount) | E03 caps: `max_memory_mb: 64` and `max_pids: 4` applied as `cgroup1 memory.limit_in_bytes`, `cgroup1 pids.max`, `RLIMIT_AS`, `RLIMIT_NPROC`; the fifth background process got "Cannot fork"; E04 with a 128 MiB cap: 6/6 held, the 400 MiB allocation raised MemoryError |

| 25 Oct 2026 | the same session: Node 22.22 and headless Chromium 153 running v86 0.5.472; guest Alpine 3.23 x86, Linux 6.18.58-0-virt, Python 3.12.15; and chroot into the same rootfs on the host kernel | E09: `landlock: Up and running.`, probe Landlock ABI 7 and cgroups v2 in the guest; `hello` 6/6 in Node, in the browser and in the chroot; E03 under P1: 443 `ENETUNREACH` (no network backend), 80 `EACCES`; under P2: write refused, read allowed; the seven example policies check and hash identically to the host |
| 25 Oct 2026 | the same session, natively, uid 0 | the profiles P0 to P4 (above): every expectation held; `sgit 0.24.0` ran under P4 |

Published with method on [sharness.ai/evidence](https://sharness.ai/evidence/index.html).
