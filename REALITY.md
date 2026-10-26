# What exists in this repository

As of 26 Oct 2026. A thing not listed here does not exist. Kept by whoever ships.

| Domain | What exists | Status |
|---|---|---|
| the policy tooling | `policy/policy.go`: `Parse`, `Check`, `Canonical`, `Hash`, `Summary`, `PathProblem`; `cmd/sharness-ai`: `policy hash FILE`, `policy check FILE` | runnable: 13 accept and 15 refuse vectors pass (`go test ./...`, 26 Oct 2026, Go 1.24) |
| a static binary | `CGO_ENABLED=0 go build` of `cmd/sharness-ai` | runnable; 2.4 MB stripped on linux/amd64, 26 Oct 2026 |
| `run`, `hello`, the launcher | nothing | planned: Landlock through `golang.org/x/sys/unix`, to be taken as the first stated exception |
| the bash client | nothing | planned |
| the servers (`net`, `fs`, `llm`) | nothing | planned, on `crypto/tls` |
| `sharness.kms` | not for Go: the collector may copy a secret | see Rust |
| the conformance vectors | `conformance/vectors.json` and `conformance/vectors/`, vendored from the policy v0 standard on sharness.ai; `conformance/fetch.sh` refreshes them | present |
| dependency exceptions taken | none | |
| CI | `.github/workflows/tests.yml`: gofmt, vet, the vendored vectors, the live vectors, the static build | present |
| measurements | none; nothing here has been measured | |
