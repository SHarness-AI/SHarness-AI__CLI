# qa: what the CLI asks to be confirmed, by someone who did not write it

The CLI's tests say the code does what its author meant. This folder asks for something the tests
cannot give: **independent confirmation**, from someone who starts where a user starts (the PyPI
page, sharness.ai, a fresh machine) and has never read the code. The askers are this repository's
members (cli@ first); the people asked are the project's synthetic users, below. Their
answers go on the website, never here.

## The files

| File | What it is |
|---|---|
| [`RELEASE.md`](RELEASE.md) | the standing checklist: run on every release, from PyPI, in a fresh environment |
| `v<X.Y.Z>.md` | the asks for one release: what changed and what we want confirmed or broken. First: [`v0.2.0.md`](v0.2.0.md) |

Every ask has an id (`R1`… in the checklist, `Q<release>-<n>` per release, e.g. `Q0.2.0-3`), a persona,
the steps a user would take, and what we expect to see. An ask says *what* to confirm; it never says
how the code does it.

## How to answer

One report per ask, on the website (the synthetic users' own section,
`content/users/`, one page per release), with:

- **the id** and **the verdict**: *Confirmed*, *Not confirmed*, *Could not run* or *Confusing*
  (it worked, but a user would not have known what to do or what it meant);
- **where**: OS and version, kernel, Landlock ABI (from `sharness-ai probe`), Python, user or root,
  laptop, VM or container, and the date. That makes the answer a measurement, in the site's words;
- **what was typed and what came back**, pasted, not summarised;
- for *Not confirmed* and *Confusing*: what you expected instead, in one sentence.

A report never contains a key, a token or the value of an environment variable: names only.

## The synthetic users: `users@sharness`

One member, one session, three people (the editor's choice, 29 Oct 2026). How to start it, with the
prompt: [`START.md`](START.md).

| Persona | Who they are | What they test first |
|---|---|---|
| newcomer | a developer who saw the announcement; a laptop, Linux or macOS; reads the PyPI page and follows it | install, the guide, `hello`, the first policy: onboarding |
| builder | wants to put a real agent or MCP server under a policy | `contain`, `profile`, `policy new` for a real tool, the `fs` door, `shell` |
| skeptic | reads every claim and tries to break it | the refusals, the "not covered" lists, the Boundary and Setting wording, bypasses |

Their rules: start from PyPI and sharness.ai, never from this repository's source; a fresh
environment for each release; paste the output; run experiments as child processes and clean up,
under the [safety rules](https://sharness.ai/design/process-tree/index.html#4-safety-rules-for-testing-inside-a-live-agent-session);
no write access here; an answer the asker does not like is still the answer.

## For the askers

When a release ships, add `qa/v<X.Y.Z>.md`: one ask per user-visible change, at least one ask that
tries to break the change, and the persona each suits. A *Not confirmed* is a bug report: fix it with
a test and say in the commit which ask it answers (`QA: Q0.2.0-3`).
