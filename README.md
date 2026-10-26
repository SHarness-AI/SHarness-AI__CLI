# SHarness-AI__Go: SHarness in Go

**Status: experiments, as of 26 Oct 2026.** This repository is the Go reference implementation of
SHarness, in the shape every language repository of the project shares
([one repository per language](https://sharness.ai/admin/briefs/2026-10-26__brief__one-repository-per-language/index.html)).
The design is at [sharness.ai](https://sharness.ai); no SHarness component (launcher, kms, net, fs,
bash, llm) is built in any language. What exists here is `REALITY.md`'s list and nothing else.

## What runs today

`policy hash` and `policy check` for a version 0 Process Behaviour Policy, against the
[policy v0 standard](https://sharness.ai/code/standards/policy-v0/) and all of its test vectors
(13 policies that must hash to a given value, 15 that must be refused), as one static binary.
Standard library only.

```
git clone https://github.com/SHarness-AI/SHarness-AI__Go && cd SHarness-AI__Go
go run ./cmd/sharness-ai policy hash  conformance/vectors/p0-hello-world.json
sha256:a6244d346ea9d7955c04defba5e67f71ae9867af618fa21d11589c7ef8449032
go test ./...                                                    # the vendored vectors
sh conformance/fetch.sh /tmp/v && SHARNESS_AI_VECTORS=/tmp/v go test ./policy/   # the live ones
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' ./cmd/sharness-ai              # a static binary
```

## Why Go, and what comes next

Go's standard library carries TLS 1.3 with client certificates (`crypto/tls`) and builds a static
binary with `CGO_ENABLED=0`; Landlock is in `golang.org/x/sys/unix`, maintained by the Go project.
So a complete implementation needs nothing from outside the Go project, and anything that must sit
on a Landlock execute allowlist (the bash client; the launcher in its end state) can be one file
with no interpreter. Two things to say honestly: the garbage collector may copy a secret before it
is zeroed, so `sharness.kms` is not for Go; and the runtime starts threads before `main`, which
count against `RLIMIT_NPROC`, so the process cap for a Go child is the `pids` cgroup, not the
rlimit (to be measured). The reasoning is in
[One standard, many languages](https://sharness.ai/articles/one-standard-many-languages.html).

Next, in order: `run` (Landlock through `x/sys/unix`, the first stated exception), `hello`, the
bash client as a static binary, and the first measured footprint of a non-Python implementation.

## The structure (shared by every language repository)

| Path | What |
|---|---|
| `README.md` | this file: what this is, its status, how to start |
| `REALITY.md` | what exists here, by domain; a thing not in it does not exist |
| `AGENTS.md`, `CLAUDE.md` | the project's guidance for agents, by reference to the site; the rules of this repository |
| `conformance/` | the standards' test vectors, vendored, and `fetch.sh` to refresh them from the site; CI runs both |
| `policy/`, `cmd/sharness-ai/` | the implementation, one package per component, each small enough to read in one sitting |
| `.github/workflows/tests.yml` | the tests on every push to `dev`; the conformance suite against the vendored and the live vectors; the static build |

Work lands on `dev`; a release is a merge to `main` and the editor's call. The module path is
`github.com/SHarness-AI/SHarness-AI__Go`; the command is `sharness-ai`, never plain `sharness`.

SHarness is unrelated to Sharness, the shell testing library.
