"""sharness.fs.disk: the local disk as the target. Every path is resolved with realpath and must
stay under the root (a symlink pointing out is a refusal, not a write); the exec bit is never set
on what is written; a write is atomic (a temp file beside it, then rename)."""
import os
import tempfile

from sharness_ai.fs.Store import OutsideRoot, Store


class Disk(Store):
    mode = "live"

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        os.makedirs(self.root, exist_ok=True)

    def _abs(self, rel: str, for_write: bool = False) -> str:
        path = os.path.join(self.root, rel)
        real = os.path.realpath(path)
        parent_real = os.path.realpath(os.path.dirname(path))
        if real != self.root and not real.startswith(self.root + os.sep):
            raise OutsideRoot(f"{rel} resolves to {real}")
        if parent_real != self.root and not parent_real.startswith(self.root + os.sep):
            raise OutsideRoot(f"the folder of {rel} resolves to {parent_real}")
        if os.path.islink(path):
            raise OutsideRoot(f"{rel} is a symlink")
        return path

    def exists(self, rel: str) -> bool:
        return os.path.isfile(self._abs(rel))

    def read(self, rel: str) -> bytes:
        with open(self._abs(rel), "rb") as f:
            return f.read()

    def write(self, rel: str, data: bytes) -> None:
        path = self._abs(rel, for_write=True)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".sharness-fs-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(tmp, 0o644)                       # never executable
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            finally:
                raise

    def append(self, rel: str, data: bytes) -> None:
        path = self._abs(rel, for_write=True)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
        fd = os.open(path, flags, 0o644)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)

    def delete(self, rel: str) -> None:
        os.unlink(self._abs(rel))

    def mkdir(self, rel: str) -> None:
        os.makedirs(self._abs(rel), exist_ok=True)

    def listing(self) -> list:
        out = []
        for dirpath, _, files in os.walk(self.root):
            for f in files:
                out.append(os.path.relpath(os.path.join(dirpath, f), self.root))
        return sorted(out)
