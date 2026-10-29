# REALITY: sharness.fs, 26 Oct 2026

- `FS.py`: the door over a Store: normalise, within the root, the rows, then the target; routes from `ACCEPTS.json`.
- `Store.py`: the Store a target implements. `disk/Disk.py`: the local disk, every path walked from the root with
  openat(2) and O_NOFOLLOW so a link anywhere in it is a refusal and nothing can be swapped between the check and
  the use; atomic writes by directory descriptor; never executable. `disk/twin/Twin.py`: a dictionary with a cap
  (256 MiB).
- `FS.normalise`: URL-decodes, drops a query or fragment, refuses `..`, absolute paths, control characters and paths
  over 1024 bytes before anything else looks at the path.
- Rows and predicates are the door kit's (`sharness_ai/door/Rows.py`): `within_root`, `refuse_secrets`,
  `max_bytes`, `append_only`.
- `vectors/vectors.json`: the conformance vectors, run against the twin first, then the disk.

Not covered by refuse_secrets, and said so: a secret in another encoding (base64, UTF-16); a secret split across appends with more than 4 KiB of the file between its parts (an append is scanned together with the file's last 4 KiB). A read returns `content` when the bytes are UTF-8 and `content_b64` otherwise, never a lossy decode. Not covered by within_root: a hard link inside the root to a file outside, which only another writer in the root could make. `GET /v0/log` is the launcher's; a caller sees its own verdicts.

Not here: rename, content by schema, a section by marker, count per interval, a transparent mode (bind or
FUSE mount), `fs.s3` or any other target, the door's own uid (the launcher's), `GET /v0/log` with filters.
Dependency exceptions taken: none.
