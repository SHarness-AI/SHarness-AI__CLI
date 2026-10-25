# Threat model

> **Status: written down, as of 25 Oct 2026; the code it describes is at the experiments stage.** This page is the long form of the table on [Why](../../design/why/index.md#threat-model). It names what SHarness protects, who it protects it from, where the trust boundaries are, and, surface by surface, what the code that exists today does about each threat and what only the designed launcher will. The CLAUDE.md rule holds throughout: the kernel is trusted; root and kernel compromise are out of scope.

## 1. What is being protected

| Asset | Where it is | What losing it means |
|---|---|---|
| **a secret** the agent's work needs: a vault key, a model API key, a token | today: on disk, on argv, in the transcript. Designed: in one process, `sharness.kms`, sealed everywhere else | anyone who reads the transcript or the disk has it, for as long as it is valid |
| **the person's data**: the workspace, a vault's contents, the files the agent may read | the machine the agent runs on | sent to a host the agent was told to reach; destroyed |
| **the person's authority**: what the agent may do on the person's behalf (push, publish, pay, delete) | the credentials and the network reach the agent has | the agent does it because a page told it to |
| **the machine** | the host, its other users and processes | a dropped file runs; a fork bomb; a socket to a daemon |
| **the evidence**: what this site says was measured | this site, the CLI's output | a pass the policy did not earn makes a reader trust what did not hold |
| **the project's supply chain**: the package on PyPI, the files on this site, the CI that makes them | GitHub, PyPI, GitHub Pages, a CDN | a reader installs or runs something the project did not write |

## 2. Who, and with what

| Actor | Has | Wants |
|---|---|---|
| **a prompt-injected agent** | everything its process can do: commands, files, network, editing a policy, printing a secret | what the injected text asked for, with the agent's whole grant |
| **untrusted content in the workspace**: a cloned repository, an archive, a vault's files | what a file can be: a symlink, a package folder with a familiar name, a hook, a file named like a policy | to run as the agent before any policy applies; to make a policy mean more than its text |
| **a tool or MCP server the agent starts** | what its process can do | the same, one step down the tree |
| **a compromised component** (designed: `fs`, `net`, `llm`, `bash`) | what its policy allows, and a reason to try what it does not | the KMS; the other components' files; the network |
| **a party on the network** | the answers to the agent's requests; a host name the injected text can mention | the data; the next injection |
| **another user or process on the machine** | the shared places: `/tmp`, Unix sockets, the cgroup tree | to tamper with what the child reads or writes |
| **a compromised upstream**: a CDN, a package index, an action's repository, a mirror | different bytes at the same address | to run on a reader's machine, in CI, or in the job that publishes |
| **root, or a kernel bug** | anything | out of scope; the microVM around the harness is the answer ([Containment §2](../../design/containment/index.md#2-with-malicious-code-inside-by-threat-class)) |

## 3. The two trust boundaries

```
 the person ───── supplies sha256:M by a channel the agent cannot write to ─────────────────────
                                           │
                                           ▼   boundary 1: the hash. Below it, text is data.
 the launcher (designed) ── verifies M; applies every policy from ABOVE the agent: a Boundary for all
   └ the agent's session ── reads untrusted text, runs tools. Today it applies policies ITSELF:
        │                    a Boundary for its children, a Setting for itself
        └ a confined child (sharness-ai run, today) ── Landlock paths and ports · namespace ·
                                                       rlimits · cgroup · no_new_privs
                                           │
                                           ▼   boundary 2: the kernel. Trusted. Root is inside it.
 the kernel, the hardware, the platform's VM
```

**Boundary 1 has a precondition the design states and this page repeats:** the person must obtain `sha256:M` independently of the agent. A hash read off the agent's own output and pasted back was chosen by the agent. The browser mockup and the playground exist so the person can compute the hash from the file themselves, on their own machine.

**Boundary 2 is the kernel.** Everything SHarness enforces is a kernel mechanism (Landlock, namespaces, cgroups, rlimits, seccomp when it comes) or a cryptographic one between processes (mutual TLS, sealing). A process inside a policy that finds a kernel bug is outside the model. A process that is root inside the same kernel is the one the policy is a Setting for.

## 4. Surface by surface

"Today" is `sharness-ai run` and `hello` on the `dev` branch as of 25 Oct 2026. "Designed" is the launcher and components, not built. Barrier kinds are ABP's: Boundary (enforced above the subject), Setting (the subject could flip it), Expectation (prose). The register row for each gap is on [Known risks](../risks/index.md).

| Surface | Threat | Today, for a confined child | Designed, for the agent itself | Not covered by anything, and said so |
|---|---|---|---|---|
| files: read | the child reads a secret, another user's data, another process's environment through `/proc` | Landlock: the listed paths only; `hello` lists neither `/proc` nor `/dev` | the same from the launcher; per-component uids as a second layer | a listed directory is listed whole (SD-08) |
| files: write | the child writes outside the workspace, or somewhere it can later run from | Landlock: the listed paths only; a writable path never carries the execute right (SR-01); a writable path that resolves elsewhere is refused before anything runs (SR-02) | `sharness.fs` as the only writer, with content rules | what it may write, it may write; `/tmp` is shared (advice) |
| files: exec | the child runs what it fetched | execute only beneath the exec list; write and exec kept apart | the process-tree execute allowlist through `sharness.bash` (E06, not run) | an interpreter on the exec list runs code from a writable path. Landlock alone cannot say otherwise; the dual-LLM split and `sharness.bash` are the design's answer |
| network: TCP | exfiltration; the host the injection named | `network: "none"`: an empty namespace where one can be made, else Landlock denies every TCP connect (ABI 4+); ports as Landlock port rules; **if neither is possible the command is refused** (SR-03) | `sharness.net` as the only client, with host, endpoint and id allowlists | v0 says ports, not hosts (SD-03) |
| network: UDP | DNS as a channel out | the namespace, when it applied | the namespace from the launcher | Landlock does not see UDP (SD-04); said on stderr |
| network: Unix sockets by path | a Docker daemon, an X server, a local MCP server, a local proxy | **nothing** (SR-08) | a mount namespace that hides them; a uid that cannot open them | said on stderr every run, in `policy check`'s advice, and in `hello` |
| processes | fork bombs | `RLIMIT_NPROC` for a non-root uid; a pids cgroup where one can be made; **for root with no cgroup the policy is refused** (SR-04) | per-component uids; `RLIMIT_NPROC=0` where a component never forks | `RLIMIT_NPROC` counts a uid's processes machine-wide |
| memory | exhaustion | `RLIMIT_AS` always; a memory cgroup where one can be made | the cgroup from the launcher | address space is not resident memory (SD-05) |
| privilege | setuid, capabilities | `no_new_privs` before the ruleset | an empty bounding set; a throwaway uid | a child that is root stays root inside its policy |
| descriptors | what was open before the policy stays open after it | every descriptor above 2 closed before the policy applies (SR-10) | the launcher opens nothing for a component | stdin, stdout, stderr are the caller's |
| environment | secrets in the environment reach the child | nothing; declared on stderr every run (SR-11) | a `process.env` row; the KMS and `sharness.llm` holding the secrets so no process needs them | until then every child sees every variable |
| signals and IPC | the child signals or traces the harness | Landlock scoping of signals and abstract sockets (ABI 6+); ptrace outside the domain refused | a pid namespace | System V IPC; shared memory within one uid |
| the policy text | text that reads as one thing and binds another | refused (SR-12 to SR-16): normalised printable paths, one value per key, integers JavaScript keeps exact, no lone surrogates | the same in the launcher; signing by the root key | what the policy *means*: the hash names it; advice remarks on it; nobody judges it |
| the applying process | it is the agent, and could skip the step | nothing: the Setting caveat, printed every `hello` (SD-01) | the launcher above the agent | this is the design's argument, not a gap it can close from inside |
| the evidence | a refusal counted when the environment, not the policy, refused | a control run without the policy for every ambiguous refusal; *inconclusive* reported (SR-09) | the launcher's acceptance test | one machine, one day; every figure on this site carries its date |

## 5. The project itself

The product is a claim made by two repositories and a package index, so the project's own surfaces are in the model.

| Surface | Threat | Where it stands, as of 25 Oct 2026 |
|---|---|---|
| the release pipeline | code that is not the project's runs in the job holding the PyPI token | fixed (SR-05): GitHub's and pypa's actions only, pinned to commits; build and publish in separate jobs; PEP 740 attestations ([Supply chain §3](../supply-chain/index.md#3-how-a-release-is-built-and-published)) |
| the branches | a push to `main` publishes; `main` and `dev` are unprotected | open (SR-24): a setting ([Hardening §3](../hardening/index.md#3-the-repositories-and-the-accounts-settings-only-a-person-can-change)) |
| the browser bench | the guest's packages downloaded unverified; the chroot form runs them as root | fixed (SR-07): every download pinned by sha256 and refused on mismatch |
| this site | a third-party script changes what a page shows | the storyboards kit loads with its integrity string (SR-20); Pyodide from jsDelivr cannot carry one (SR-25, accepted, with what a compromise could and could not do) |
| the code published on this site | a file at a published path changes after a reader pinned it | fixed by construction: immutable release paths with a manifest of hashes; the gate fails if a byte changes ([Supply chain §5](../supply-chain/index.md#5-the-code-on-this-site-immutable-paths)) |
| the agents that write here | an agent following injected text in something it reads, or a leaked session token | the same rules as any contributor: a pull request, the gate, the register; the lock-down list asks for required reviews on `main` |

## 6. What the model leaves out, on purpose

- **Root and the kernel.** Said above and on every page that could suggest otherwise.
- **Side channels**: timing, cache, the size and timing of allowed messages ([Containment §2](../../design/containment/index.md#2-with-malicious-code-inside-by-threat-class)).
- **The model provider.** What the model does with the text it receives is the provider's model, not this one.
- **The correctness of a policy.** A policy that allows a push to host X allows a push to host X. The defences are a narrower mandate and the dual-LLM split; no sandbox fixes an over-wide mandate.
- **Physical access, and the person's own machine before the agent runs.**

Sources: [Why: threat model](../../design/why/index.md#threat-model); [Policies §2 and §8](../../design/policies/index.md); [Containment](../../design/containment/index.md); [What a process can do](../../design/surface/index.md); the review on [Reviews](../reviews/index.md); the kernel's [Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html) for what Landlock does and does not hook.
