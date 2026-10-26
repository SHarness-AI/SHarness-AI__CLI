"""The abstraction stack: one policy, written at the depth you need.

Six levels (sharness.ai/design/levels): 5 intent, 4 profile, 3 rows in plain nouns, 2 doors and
targets, 1 mechanisms, 0 the ground. Each level is a project of its own here (`l5/`, `l4/`,
`l3/`), a pure compiler from its document to the level below, deterministic, so the hash of what
a person wrote names, through the chain, what the kernel is told. Chain walks a document down.
In this MVP level 2 is the v0 policy (the kernel as the only door), level 1 is derived from it,
level 0 is what `hello` measured. Standard library only; the canonical form of each level is
proposed here for pbp@sharness to correct (sharness.ai/admin/briefs/2026-10-26__brief__the-mashup-in-code/).
"""
from sharness_ai.level.Chain import Chain, Step, level_of

__all__ = ["Chain", "Step", "level_of"]
