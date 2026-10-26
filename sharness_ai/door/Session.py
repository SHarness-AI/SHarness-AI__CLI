"""A session: one CA, one certificate per role, the CA key destroyed. E05 as code.

    Session.new(dir, roles)   openssl: P-256 keys, TLS 1.3 certificates with SAN URI
                              spiffe://<session>/<role> and DNS localhost; CA pathlen 0; the CA key
                              is deleted before this returns, so the set of identities is closed.
    Session.load(dir)         what a door or a client needs: its own cert and key, the CA cert.

`openssl` is used by subprocess with fixed arguments (reuse before build; no dependency). Where it
is absent, new() raises SessionError with the hint. Validity is one day (openssl 3.0's `-days`);
the design's two hours wait on `-not_after`, which needs a newer openssl."""
import json
import os
import secrets
import shutil
import subprocess
import time

ROLES = ("app", "fs", "net", "bash", "llm", "kms", "launcher")
# the edge matrix (sharness.ai/design/architecture #edges): who may call whom; deny by default
EDGES = {("app", "fs"), ("app", "net"), ("app", "bash"), ("app", "llm"), ("net", "kms"), ("llm", "kms"), ("bash", "net"),
         ("launcher", "fs"), ("launcher", "net"), ("launcher", "bash"), ("launcher", "llm"), ("launcher", "kms")}
SPIFFE = "spiffe://{session}/{role}"


class SessionError(RuntimeError):
    pass


def openssl() -> str:
    path = shutil.which("openssl")
    if not path:
        raise SessionError("openssl is not on this machine: a session's certificates cannot be issued. "
                           "Install it (every Linux distribution carries it; the bench's guest bakes one in)")
    return path


def _run(args: list, cwd: str):
    r = subprocess.run(args, cwd=cwd, capture_output=True, text=True)  # noqa: S603 - fixed argv, openssl found by which
    if r.returncode:
        raise SessionError(f"openssl failed: {' '.join(args[:3])}: {r.stderr.strip()[-300:]}")


class Session:
    def __init__(self, directory: str, session_id: str, roles: tuple, created: str):
        self.dir, self.id, self.roles, self.created = directory, session_id, tuple(roles), created

    @classmethod
    def new(cls, directory: str, roles=("app", "fs"), days: int = 1) -> "Session":
        for r in roles:
            if r not in ROLES:
                raise SessionError(f"unknown role {r!r}; the roles are {', '.join(ROLES)}")
        if not 1 <= days <= 3650:
            raise SessionError("days must be 1 to 3650")
        ssl_bin = openssl()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        sid = secrets.token_hex(8)
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
        old_umask = os.umask(0o077)                         # every key is born 0600; no window to tighten
        try:
            _run([ssl_bin, "req", "-x509", *ec, "-keyout", "ca.key", "-out", "ca.crt", "-days", str(days),
                  "-subj", f"/CN=sharness session {sid}", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                  "-addext", "keyUsage=critical,keyCertSign"], directory)
            for role in roles:
                _run([ssl_bin, "req", *ec, "-keyout", f"{role}.key", "-out", f"{role}.csr", "-subj", f"/CN={role}",
                      "-addext", f"subjectAltName=URI:{SPIFFE.format(session=sid, role=role)},DNS:localhost",
                      "-addext", "basicConstraints=critical,CA:FALSE"], directory)
                _run([ssl_bin, "x509", "-req", "-in", f"{role}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
                      "-out", f"{role}.crt", "-days", str(days), "-copy_extensions", "copy"], directory)
                os.unlink(os.path.join(directory, f"{role}.csr"))
        finally:
            os.umask(old_umask)
            for leftover in ("ca.key", "ca.srl"):            # the CA key dies whatever happened: the set of identities is closed
                try:
                    os.unlink(os.path.join(directory, leftover))
                except OSError:
                    pass
        for name in os.listdir(directory):
            os.chmod(os.path.join(directory, name), 0o600 if name.endswith(".key") else 0o644)
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(os.path.join(directory, "session.json"), "w", encoding="utf-8") as f:
            json.dump({"schema": "sharness-ai.session/v0", "id": sid, "roles": list(roles), "created": created,
                       "edges": sorted(f"{a}->{b}" for a, b in EDGES if a in roles and b in roles),
                       "ca_key": "destroyed after issuing"}, f, indent=1)
        return cls(directory, sid, roles, created)

    @classmethod
    def load(cls, directory: str) -> "Session":
        try:
            with open(os.path.join(directory, "session.json"), encoding="utf-8") as f:
                meta = json.load(f)
        except (OSError, ValueError) as e:
            raise SessionError(f"no session in {directory}: {e}; sharness-ai session new --dir {directory}") from None
        return cls(directory, meta["id"], tuple(meta["roles"]), meta.get("created", ""))

    def cert(self, role: str) -> str:
        return os.path.join(self.dir, f"{role}.crt")

    def key(self, role: str) -> str:
        return os.path.join(self.dir, f"{role}.key")

    @property
    def ca(self) -> str:
        return os.path.join(self.dir, "ca.crt")

    def spiffe(self, role: str) -> str:
        return SPIFFE.format(session=self.id, role=role)

    @staticmethod
    def default_dir() -> str:
        base = os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
        return os.path.join(base, "sharness-ai", "session")
