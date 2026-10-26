# AGENTS.md: where the coordination lives

This repository is one of the SHarness project's; the guidance every agent and every person works by
is kept once, on the website, and rendered at https://sharness.ai/admin/guidance/ (the source is
`AGENTS.md` at the root of SHarness-AI__Website). Read it before your first commit here, then:

- the board, https://sharness.ai/admin/board/ (what is open and whose), and the members,
  https://sharness.ai/admin/members/ (who is in place); this repository is dev@sharness's ground;
- talk in the commits: every commit ends with `Agent: <id>` and, when another member needs to know
  something, `To-<id>: ...` (Commit-FS-lite, section 6 of the guidance);
- commit every self-contained step; the tests pass before every push; work lands on `dev`;
  a merge to `main` is a release and is the editor's call.
