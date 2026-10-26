# SHarness-AI__Rust: SHarness in Rust

**Status: the structure only, as of 26 Oct 2026. Nothing is built.** This repository is the Rust
reference implementation of SHarness, in the shape every language repository of the project
shares ([one repository per language](https://sharness.ai/admin/briefs/2026-10-26__brief__one-repository-per-language/index.html)).
The design is at [sharness.ai](https://sharness.ai); no SHarness component (launcher, kms, net,
fs, bash, llm) is built in any language. The standards and their test vectors are on the site:
[policy v0](https://sharness.ai/code/standards/policy-v0/), vendored under `conformance/`.

## Why Rust, and what comes first

The design names Rust for two pieces ([Languages](https://sharness.ai/code/languages/)): the
**bash client**, which must be a static binary because an interpreter on a Landlock execute
allowlist is permission to execute anything, and **`sharness.kms`**, where memory hygiene decides
the security and a language without a garbage collector can zero a secret where it lived.
Those are the first targets here, in that order, after the KMS protocol is settled in Python (E08).

The policy tooling (`policy hash`, `policy check`) comes to Rust too, against the same vectors.
Rust's standard library has no JSON parser, so that piece takes `serde_json`, pinned, as a stated
exception to the project's no-dependencies rule, the same kind of exception as `rustls` for the
mutual-TLS servers and `cryptography` in Python. The exceptions are listed in `REALITY.md` as they
are taken, never silently.

## The structure (shared by every language repository)

| Path | What |
|---|---|
| `README.md` | this file: what this is, its status, how to start |
| `REALITY.md` | what exists here, by domain; a thing not in it does not exist |
| `AGENTS.md`, `CLAUDE.md` | the project's guidance for agents, by reference to the site; the rules of this repository |
| `conformance/` | the standards' test vectors, vendored, and `fetch.sh` to refresh them from the site; CI runs both |
| `src/`, `tests/` | the implementation, one module per component, each small enough to read in one sitting |
| `.github/workflows/tests.yml` | the tests on every push to `dev`; the conformance suite against the vendored and the live vectors |

Work lands on `dev`; a release is a merge to `main` and is the editor's call. The crate name on
crates.io will be `sharness-ai` (unclaimed on 25 Oct 2026); never plain `sharness`.

SHarness is unrelated to Sharness, the shell testing library.
