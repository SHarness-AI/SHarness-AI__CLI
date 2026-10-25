# sharness-ai: notes for agents working in this repository

- **What this is.** The SHarness CLI, at the *experiments* stage. The design is on
  https://sharness.ai (markdown at `/<page>/index.md`, index at `/llms.txt`). No SHarness
  component (launcher, kms, net, fs, bash, llm) is built. Say so wherever status is stated.
- **Status words.** *Measured* only with a method, an environment and a date. Everything else
  is *designed*, *proposed* or *planned*. *Runnable* means the code is here and its tests pass.
- **Threat model.** The kernel is trusted; root and kernel compromise are out of scope. Never
  claim protection against them. A policy a process applies to its own children is a Boundary
  for them and a Setting for itself: say which, every time.
- **Code.** Standard library only (no runtime dependencies; `experiments/browser/` pins v86 for E09's
  emulated guest, a test bench, not part of the package). Each module small enough to read
  in one sitting; the design's targets are launcher ≤ 400 lines, component ≤ 300. Python 3.11+.
  Reuse Linux and Python before building: Landlock, namespaces, seccomp, cgroups, `ssl`.
- **Tests.** `python -m pytest tests/unit`. Classes `Test_*`, functions `test_*`. Tests that
  need Landlock skip where it is absent, so the suite runs on any OS.
- **Names.** Brand *SHarness*; command `sharness-ai` (never plain `sharness`, which is the
  shell test library's package); import `sharness_ai`; env prefix `SHARNESS_AI_`; components
  `sharness.<role>`. No model names in committed text.
- **Releases.** Work lands on `dev`. Merging `dev` into `main` runs `.github/workflows/workflow.yml`:
  tests, version bump (CI owns `sharness_ai/version` and the version in `pyproject.toml`), tag,
  PyPI via Trusted Publishing. Do not bump the version by hand.
- **Experiments.** Numbered in `experiments/README.md`; each says where it runs and what it
  does not show. New measurements go to the site's Evidence page with method and date.
- **Coordination.** The board, the members, the updates and the guidance for every agent are on
  https://sharness.ai/admin/ ; `AGENTS.md` beside this file says how this repository joins in. Every
  commit carries an `Agent: <id>` trailer.
