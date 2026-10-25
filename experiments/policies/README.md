# Example Process Behaviour Policies (v0)

Seven v0 policies: two minimal examples and five profiles, P0 to P4, from a hello world up to
sgit. All share one shape ([`policy.py`](../../sharness_ai/policy.py)): `files` (read, write,
exec, as path prefixes), `network` (`"none"` or TCP ports a child may connect to) and `process`
(`no_new_privs`, an address-space cap, a process-count cap). The workspace is `/work` in every
profile; change the paths, the hash changes, and that is the point: the hash names the policy.

| File | Who it is for | Writes | Network | Caps |
|---|---|---|---|---|
| `deny-all-example.json` | E02/E03: the smallest policy | none | none | none |
| `allow-https-example.json` | E03: deny-all plus port 443 | none | TCP 443 | none |
| `p0-hello-world.json` | a hello world | none | none | 64 MiB, 8 processes |
| `p1-agent-session.json` | a coding agent's session (a Claude Code session, an orchestrator) | `/work`, `/tmp` | TCP 443 | 4 GiB, 512 |
| `p2-tool-server.json` | a tool or MCP server on stdio | none | none | 512 MiB, 16 |
| `p3-newsroom-agent.json` | the sgit.ai newsroom agent: a vault checkout in, articles out | `/work/out` | TCP 443 | 1 GiB, 64 |
| `p4-sgit.json` | the sgit CLI: the vault checkout and `/tmp` | `/work/vault`, `/tmp` | TCP 443 | 512 MiB, 16 |

```
sharness-ai policy check experiments/policies/p1-agent-session.json
sharness-ai policy hash  experiments/policies/p1-agent-session.json
sharness-ai run --policy experiments/policies/p2-tool-server.json -- my-tool-server
sharness-ai policy translate experiments/policies/p1-agent-session.json --to claude-code
```

How they compose: P1 is what a launcher applies to the agent's session. The session applies P2
to each tool it starts: a Boundary for the tool, a Setting for the session, which could have
skipped it. Only the launcher above the session makes P1 a Boundary for the agent; that launcher
is the design, not yet code. P3 and P4 are two processes of one workflow with different writes:
the agent writes articles, sgit writes the vault, neither can do the other's job.

What v0 cannot say yet, in order of the roadmap: **hosts** (ports only; the vault host and the
model API are `sharness.net`'s allowlist), **UDP** (Landlock does not see it, so DNS resolves
unless `network: "none"` gets its empty namespace), **uids and seccomp**, **signing** and
**layers composed by intersection** (`layer` is a label here). `translate` prints, per target,
what else that target cannot enforce.

Two things learned writing them. The ELF interpreter must be executable: on musl systems it is
`/lib/ld-musl-*.so.1`, so `exec` lists `/lib`, or no dynamic binary starts (seen in the E09
guest, where `allow-https-example`, with `/usr` and `/bin` only, could not start `python3`;
on a merged-`/usr` glibc system `/lib64` is a link into `/usr`, which hid it). And paths that
do not exist on a machine are skipped, so one policy file serves Alpine and Ubuntu.
