# Notes for agents working in this repository

- **What this is.** A reference implementation of SHarness in one language, against the standards
  on https://sharness.ai/code/standards/ (markdown at `/<page>/index.md`, index at `/llms.txt`).
  SHarness is at the *experiments* stage: no SHarness component (launcher, kms, net, fs, bash, llm)
  is built, in this language or any other. Say so wherever status is stated. `REALITY.md` says
  what exists here; keep it current.
- **Status words.** *Measured* only with a method, an environment and a date. Everything else is
  *designed*, *proposed* or *planned*. *Runnable* means the code is here and its tests pass.
- **Threat model.** The kernel is trusted; root and kernel compromise are out of scope. A policy a
  process applies to its own children is a Boundary for them and a Setting for itself: say which.
- **The standard decides.** The conformance vectors under `conformance/` are the standard's; this
  implementation passes them or says in `REALITY.md` which it does not. Never edit a vector here:
  a change to the standard happens on the site (dev@sharness, with pbp@sharness for the policy's
  shape), and `conformance/fetch` brings it in.
- **Code.** The language's standard library only; a dependency is a stated, pinned exception
  listed in `REALITY.md`. Each module small enough to read in one sitting (the design's targets:
  launcher at most 400 lines, a component at most 300). Say what the runtime adds to the attack
  surface where it matters (an interpreter on an execute allowlist; threads against a process
  cap; a collector that copies a secret).
- **Names.** Brand *SHarness*; command `sharness-ai` (never plain `sharness`); env prefix
  `SHARNESS_AI_`; components `sharness.<role>`. No model names in committed text.
- **Releases.** Work lands on `dev`; a merge of `dev` into `main` is a release and the editor's call.
- Coordination: `AGENTS.md` here, and the site's guidance it points to.
