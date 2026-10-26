# What exists in this repository

As of 26 Oct 2026. A thing not listed here does not exist. Kept by whoever ships.

| Domain | What exists | Status |
|---|---|---|
| the policy tooling | `src/policy.js`: `scan`, `parse`, `check`, `canonical`, `policyHash`, `summary`; `bin/sharness-ai.js`: `policy hash FILE`, `policy check FILE` | runnable: 13 accept and 15 refuse vectors pass (`npm test`, 26 Oct 2026, Node 22) |
| the browser build | `src/policy.js` is one ES module with no imports; it runs in a page as it is | runnable; not yet wired into the site's mockup |
| `run`, `hello`, the launcher | nothing | planned: delegated to a helper binary that can reach the kernel |
| the servers (`net`, `fs`, `llm`) | nothing | planned, on Node's `tls` module |
| `translate` | nothing | planned |
| the conformance vectors | `conformance/vectors.json` and `conformance/vectors/`, vendored from the policy v0 standard on sharness.ai; `conformance/fetch.mjs` refreshes them | present |
| dependency exceptions taken | none | |
| CI | `.github/workflows/tests.yml`: `npm test` on Node 20 and 22, then the same against the live vectors | present |
| measurements | none; nothing here has been measured | |
