"""sharness.fs.disk.twin: the disk simulated. The same face as fs.disk (the door's code does not
change); the backend is a dictionary, so a conformance suite runs anywhere, offline, in a test
or in a browser tab, and leaves nothing behind. `.twin` is the terminal suffix: the thing before
it is running as a simulation of what is on the other side (sharness.ai/design/pbp §6)."""
from sharness_ai.fs.Store import Store


MAX_TOTAL = 256 << 20          # the twin is a simulation; a caller cannot grow it without bound


class Twin(Store):
    mode = "twin"

    def __init__(self, max_total: int = MAX_TOTAL):
        self.files = {}
        self.dirs = set()
        self.max_total = max_total

    def _room(self, extra: int):
        if sum(len(v) for v in self.files.values()) + extra > self.max_total:
            raise OSError(28, "the twin is full (its cap)")      # ENOSPC, as a disk would say

    def exists(self, rel: str) -> bool:
        return rel in self.files

    def read(self, rel: str) -> bytes:
        return self.files[rel]

    def write(self, rel: str, data: bytes) -> None:
        self._room(len(data) - len(self.files.get(rel, b"")))
        self.files[rel] = bytes(data)

    def append(self, rel: str, data: bytes) -> None:
        self._room(len(data))
        self.files[rel] = self.files.get(rel, b"") + bytes(data)

    def delete(self, rel: str) -> None:
        del self.files[rel]

    def mkdir(self, rel: str) -> None:
        self.dirs.add(rel)

    def listing(self) -> list:
        return sorted(self.files)
