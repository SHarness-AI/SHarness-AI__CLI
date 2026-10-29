# sharness.fs: the only writer

The door for files: paths, operations and content, whatever the storage. The door alone is the API
(`ACCEPTS.json`); every leaf names where it sends (`EMITS.json`): `fs.disk`, the local disk, the one
target the kernel also bounds; `fs.disk.twin`, the disk simulated in memory, the same face.

| Rule | Held by | Verdict |
|---|---|---|
| a path outside the root (`..`, absolute, a symlink pointing out) | the door, always | `403 within_root` |
| bytes that parse as a private key, a clear vault key, an API token | the door, always | `403 refuse_secrets` |
| a body over `max_bytes` (64 MiB unless a row says less) | the door | `403 max_bytes` |
| a write or delete where a row says `append_only` | the door | `403 append_only` |
| the app's own `open(O_WRONLY)` on the root, bypassing the door | the kernel, once the app's policy has no write right there | `EACCES` |

`sharness-ai fs serve --target disk|disk.twin --root DIR --session DIR`; `fs hello`, `fs put`, `fs append`,
`fs get`, `fs rm`; `sharness-ai door conformance fs.disk.twin` runs `vectors/vectors.json`.

**Status: runnable, proposed (26 Oct 2026).** A Boundary for the app only when the launcher (not built)
gives this door its own uid and the app's policy no write right to the root; until then a Setting, said
on every `hello`. Standard library only.
