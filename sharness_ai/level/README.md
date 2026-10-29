# sharness_ai.level: the abstraction stack

One policy, written at the depth you need. Six levels (sharness.ai/design/levels), each compiling
deterministically into the one below, so the hash of what a person wrote names what the kernel is told.
Each level here is a project of its own (`l5/`, `l4/`, `l3/`), with its README, REALITY.md, ACCEPTS.json,
EMITS.json and vectors; `Chain.py` walks a document down and reports in the person's nouns.

| Level | Project | Accepts | Emits | Verb |
|---|---|---|---|---|
| 5 intent | `l5/` | a sentence with blanks | a level-4 profile with its blanks | `sharness-ai contain` |
| 4 profile | `l4/` | a profile name and the blanks filled | a level-3 document | `sharness-ai profile` |
| 3 rows | `l3/` | the v0 shape with `sites` in plain nouns | the v0 policy (level 2 in this MVP) | `sharness-ai policy` |
| 2 manifest | `policy.py` | the v0 policy; the kernel as the only door | | `sharness-ai policy`, `components` |
| 1 kernel | derived in `Chain.py` | | what Landlock, rlimits and cgroups are told | `run --verbose`, `translate` |
| 0 ground | `hello`, `doctor` | | the measured result | `hello` |

`sharness-ai explain FILE` draws any document down the chain, one box per level, a hash beside each.

**Status: runnable, proposed.** The compilers run and their vectors pass; the canonical form of each
level is this package's proposal for pbp@sharness to correct. Standard library only. Design:
sharness.ai/admin/briefs/2026-10-26__brief__the-mashup-in-code/ and the article "From a sentence to the kernel".
