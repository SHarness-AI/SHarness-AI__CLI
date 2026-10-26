"""sharness.fs.disk: the local disk as the target.

Every path is walked component by component from the root with openat(2) and O_NOFOLLOW, so a
symbolic link anywhere in it is a refusal, not a write, and nothing can be swapped between the
check and the use (the check is the open). Writes are atomic (a temporary name in the same
directory, then rename, both by directory descriptor), never executable, and never follow a link
at the final component either."""
import errno
import os
import secrets
import stat

from sharness_ai.fs.Store import OutsideRoot, Store

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
try:
    DIR_FLAGS |= os.O_CLOEXEC
except AttributeError:
    pass


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


class Disk(Store):
    mode = "live"

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        os.makedirs(self.root, exist_ok=True)

    def _dir(self, rel_dir: str, create: bool = False) -> int:
        """A descriptor for the directory `rel_dir` under the root, opened one component at a time
        with O_NOFOLLOW; a component that is a symlink, or missing without `create`, is OutsideRoot."""
        fd = os.open(self.root, DIR_FLAGS)
        try:
            for part in [p for p in rel_dir.split("/") if p]:
                try:
                    nxt = os.open(part, DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o755, dir_fd=fd)
                    nxt = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = nxt
            return fd
        except OutsideRoot:
            os.close(fd)
            raise
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR):     # O_DIRECTORY|O_NOFOLLOW on a link gives ENOTDIR on Linux
                try:
                    st = os.stat(part, dir_fd=fd, follow_symlinks=False)
                    kind = "a symbolic link" if stat.S_ISLNK(st.st_mode) else "a file, not a directory"
                except OSError:
                    kind = "a symbolic link or a file"
                os.close(fd)
                raise OutsideRoot(f"{part} in {rel_dir} is {kind}") from None
            os.close(fd)
            raise

    @staticmethod
    def _split(rel: str):
        d, _, name = rel.rpartition("/")
        return d, name

    def _open_file(self, rel: str, flags: int, mode: int = 0o644, create_dirs: bool = False) -> int:
        d, name = self._split(rel)
        dfd = self._dir(d, create=create_dirs)
        try:
            try:
                return os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=dfd)
            except OSError as e:
                if e.errno == errno.ELOOP:                       # the final component is a symlink
                    raise OutsideRoot(f"{rel} is a symbolic link") from None
                raise
        finally:
            os.close(dfd)

    def exists(self, rel: str) -> bool:
        d, name = self._split(rel)
        try:
            dfd = self._dir(d)
        except (FileNotFoundError, OutsideRoot):
            return False
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            return stat.S_ISREG(st.st_mode)
        except FileNotFoundError:
            return False
        finally:
            os.close(dfd)

    def read(self, rel: str) -> bytes:
        fd = self._open_file(rel, os.O_RDONLY)
        try:
            chunks = []
            while True:
                b = os.read(fd, 1 << 20)
                if not b:
                    return b"".join(chunks)
                chunks.append(b)
        finally:
            os.close(fd)

    def write(self, rel: str, data: bytes) -> None:
        d, name = self._split(rel)
        dfd = self._dir(d, create=True)
        tmp = f".sharness-fs-{secrets.token_hex(8)}.tmp"      # unique per call: two writers to one name never collide
        made = False
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
            made = True
            try:
                _write_all(fd, data)
                os.fchmod(fd, 0o644)                           # never executable
            finally:
                os.close(fd)
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)   # atomic; replaces a link at `name` without following it
        except BaseException:
            if made:
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except OSError:
                    pass
            raise
        finally:
            os.close(dfd)

    def append(self, rel: str, data: bytes) -> None:
        fd = self._open_file(rel, os.O_WRONLY | os.O_APPEND | os.O_CREAT, create_dirs=True)
        try:
            _write_all(fd, data)
        finally:
            os.close(fd)

    def delete(self, rel: str) -> None:
        d, name = self._split(rel)
        dfd = self._dir(d)
        try:
            os.unlink(name, dir_fd=dfd)
        finally:
            os.close(dfd)

    def mkdir(self, rel: str) -> None:
        os.close(self._dir(rel, create=True))

    def listing(self) -> list:
        out = []
        for dirpath, dirnames, files in os.walk(self.root, followlinks=False):
            dirnames[:] = [x for x in dirnames if not os.path.islink(os.path.join(dirpath, x))]
            for f in files:
                p = os.path.join(dirpath, f)
                if not os.path.islink(p) and not f.startswith(".sharness-fs-"):
                    out.append(os.path.relpath(p, self.root))
        return sorted(out)
