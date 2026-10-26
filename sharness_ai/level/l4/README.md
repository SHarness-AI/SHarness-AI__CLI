# level 4: profiles

A profile is a level-3 template a vendor ships beside a tool, with blanks (`$workspace`, `$sites`, `$secrets`, `$memory_mb`, `$pids`) the person fills. The six here are the example policies P0 to P5 as templates. Compilation is substitution and nothing else: the same blanks give the same level-3 document and hash.

Status: runnable, proposed (26 Oct 2026). Verb: `sharness-ai profile list|show NAME`; `contain --profile NAME`.
