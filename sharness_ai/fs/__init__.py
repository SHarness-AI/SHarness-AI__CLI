"""sharness.fs: the only writer. The door alone is the API (paths, operations, content); every
leaf names where it sends: `fs.disk` (the local disk, the one target the kernel also bounds) and
`fs.disk.twin` (the disk simulated, memory-backed). Rows: within the root always, refuse clear
secrets always, max_bytes, append_only on a path. Standard library only.
Status: runnable, proposed (26 Oct 2026): a Setting for the app until the launcher gives this
door its own uid and the app's policy no write right to the root."""
from sharness_ai.fs.FS import FS

__all__ = ["FS"]
