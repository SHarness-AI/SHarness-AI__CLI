# SHarness-AI__JS: SHarness in JavaScript, for Node and the browser

**Status: experiments, as of 26 Oct 2026.** This repository is the JavaScript reference implementation
of SHarness, in the shape every language repository of the project shares
([one repository per language](https://sharness.ai/admin/briefs/2026-10-26__brief__one-repository-per-language/index.html)).
The design is at [sharness.ai](https://sharness.ai); no SHarness component (launcher, kms, net, fs,
bash, llm) is built in any language. What exists here is `REALITY.md`'s list and nothing else.

## What runs today

`policy hash` and `policy check` for a version 0 Process Behaviour Policy, against the
[policy v0 standard](https://sharness.ai/code/standards/policy-v0/) and all of its test vectors
(13 policies that must hash to a given value, 15 that must be refused), in Node 20+ and in a browser.
No dependencies: `JSON`, `TextEncoder` and WebCrypto.

```
git clone https://github.com/SHarness-AI/SHarness-AI__JS && cd SHarness-AI__JS
node bin/sharness-ai.js policy hash  conformance/vectors/p0-hello-world.json
sha256:a6244d346ea9d7955c04defba5e67f71ae9867af618fa21d11589c7ef8449032
node bin/sharness-ai.js policy check conformance/vectors/p2-tool-server.json
npm test                      # the vendored vectors
npm run conformance:live      # the vectors as published on sharness.ai now
```

In a page: `import { canonical, check, policyHash } from './src/policy.js'`. The same file, no build.

## What a JavaScript runtime can and cannot carry

Node's standard library can carry the standards (this) and the mutual-TLS servers (`net`, `fs`,
`llm`: its `tls` module does TLS 1.3 with client certificates). It cannot reach the kernel: there
are no raw system calls in it, so a `run` here will hand the policy and the command to a helper
binary that can (the Go or Rust `run`, or bubblewrap), the way Claude Code's own sandbox does.
The browser carries the standards only, and is its own enforcer (Content-Security-Policy as a
translate target, proposed). The `node` binary is an interpreter and never belongs on a Landlock
execute allowlist. The reasoning is in
[One standard, many languages](https://sharness.ai/articles/one-standard-many-languages.html).

## The structure (shared by every language repository)

| Path | What |
|---|---|
| `README.md` | this file: what this is, its status, how to start |
| `REALITY.md` | what exists here, by domain; a thing not in it does not exist |
| `AGENTS.md`, `CLAUDE.md` | the project's guidance for agents, by reference to the site; the rules of this repository |
| `conformance/` | the standards' test vectors, vendored, and `fetch.mjs` to refresh them from the site; CI runs both |
| `src/`, `bin/`, `test/` | the implementation, one module per component, each small enough to read in one sitting |
| `.github/workflows/tests.yml` | the tests on every push to `dev`; the conformance suite against the vendored and the live vectors |

Work lands on `dev`; a release to npm (`sharness-ai`, unclaimed on 25 Oct 2026; never plain
`sharness`) is a merge to `main` and the editor's call.

SHarness is unrelated to Sharness, the shell testing library.
