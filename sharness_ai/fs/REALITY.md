# REALITY: sharness.fs, 26 Oct 2026

- `FS.py`: the door over a Store: normalise, within the root, the rows, then the target; routes from `ACCEPTS.json`.
- `Store.py`: the Store a target implements. `disk/Disk.py`: the local disk (realpath containment, no symlink
  follow, atomic write, never executable). `disk/twin/Twin.py`: a dictionary.
- Rows and predicates are the door kit's (`sharness_ai/door/Rows.py`): `within_root`, `refuse_secrets`,
  `max_bytes`, `append_only`.
- `vectors/vectors.json`: the conformance vectors, run against the twin first, then the disk.

Not here: rename, content by schema, a section by marker, count per interval, a transparent mode (bind or
FUSE mount), `fs.s3` or any other target, the door's own uid (the launcher's), `GET /v0/log` with filters.
Dependency exceptions taken: none.
