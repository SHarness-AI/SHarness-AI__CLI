# What exists in this repository

As of 26 Oct 2026. A thing not listed here does not exist. Kept by whoever ships.

| Domain | What exists | Status |
|---|---|---|
| the policy tooling (`policy hash`, `policy check`) | nothing | planned; the vectors it must pass are in `conformance/` |
| the bash client (a static binary) | nothing | planned, first target |
| `sharness.kms` | nothing | planned, after E08 settles the protocol in Python |
| the servers (`net`, `fs`, `llm`) | nothing | planned; `rustls`, pinned, will be the stated exception |
| the conformance vectors | `conformance/vectors.json` and `conformance/vectors/`, vendored from the policy v0 standard on sharness.ai | present |
| dependency exceptions taken | none | |
| CI | the vendored vectors are present and parse; nothing else runs | present |
