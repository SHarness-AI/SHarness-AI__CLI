"""One shell under the harness: a session, a unique uid where possible, the net door for that uid,
the shell's policy compiled from a sentence with its network row replaced by the proxy's port, the
shell started in a network namespace of its own (loopback only, the proxy's socket on it) with
HTTPS_PROXY pointing at the door, and the live page. Everything is undone on exit (every process of
the uid stopped, the user removed unless kept, the doors stopped)."""
import json
import os
import pwd
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

from sharness_ai.door.Session import Session
from sharness_ai.launcher import Netns
from sharness_ai.launcher.UI import UI
from sharness_ai.launcher.Watch import processes
from sharness_ai.level import Chain
from sharness_ai.net import NET
from sharness_ai.net.proxy.Proxy import Proxy

ROLES = ("app", "fs", "net", "launcher")
PKG_PARENT = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class LaunchError(RuntimeError):
    pass


class Launcher:
    def __init__(self, workspace: str, sites: list, profile: str = "coding-agent", agent: str = "shell", unique_uid: bool = None,
                 memory_mb: int = None, pids: int = None, ui: bool = True, session_dir: str = None, keep_user: bool = False):
        self.workspace = os.path.realpath(workspace)
        self.sites, self.profile, self.agent = list(sites or []), profile, agent
        self.unique_uid = (os.geteuid() == 0 and shutil.which("useradd") is not None) if unique_uid is None else unique_uid
        self.memory_mb, self.pids, self.want_ui, self.keep_user = memory_mb, pids, ui, keep_user
        self.session_dir = session_dir
        self.uid = self.gid = None
        self.username = None
        self.net = self.ui = self.session = None
        self.home = None
        self.chain = None
        self.v0 = None
        self.inner = None                                   # the proxy on the shell's own namespace
        self.cleanup = ""

    # ---- the plan: the sentence, compiled, with the proxy's port as the only network row ----------
    def compile(self, proxy_port: int) -> dict:
        contain = {"agent": self.agent, "workspace": self.workspace, "sites": self.sites, "secrets": [], "profile": self.profile}
        budget = {k: v for k, v in (("memory_mb", self.memory_mb), ("pids", self.pids)) if v is not None}
        if budget:
            contain["budget"] = budget
        self.chain = Chain.from_document({"pbp": 1, "level": 5, "contain": contain})
        v0 = json.loads(json.dumps(self.chain.v0))
        v0["network"] = {"connect_tcp_ports": [proxy_port]}          # the kernel holds this port; sharness.net holds the hosts
        v0["id"] = f"{self.agent}-shell"
        if self.home:
            v0["files"]["read"] = sorted(set(v0["files"]["read"]) | {self.home})
            v0["files"]["write"] = sorted(set(v0["files"]["write"]) | {self.home})
        v0.setdefault("notes", "")
        v0["notes"] = f"sharness-ai shell: hosts {self.sites} held by sharness.net.proxy on port {proxy_port}; the kernel holds the rest"
        self.v0 = v0
        return v0

    # ---- the uid ----------------------------------------------------------------------------------
    def make_user(self):
        if not self.unique_uid:
            self.uid, self.gid = os.geteuid(), os.getegid()
            return
        name = f"sharness-{secrets.token_hex(3)}"
        r = subprocess.run(["useradd", "--system", "--no-create-home", "--shell", "/bin/sh", name],  # noqa: S603,S607 - a fixed program, a generated name
                           capture_output=True, text=True)
        if r.returncode:
            raise LaunchError(f"useradd failed: {r.stderr.strip()}; use --no-user to run the shell as this uid (a Setting)")
        pw = pwd.getpwnam(name)
        self.username, self.uid, self.gid = name, pw.pw_uid, pw.pw_gid
        self.home = tempfile.mkdtemp(prefix=f"sharness-home-{name}-")
        os.chown(self.home, self.uid, self.gid)
        os.chmod(self.home, 0o700)

    def check_access(self):
        """Can the shell's uid enter and write the workspace? Checked as that uid in a throwaway child,
        before any door starts; a workspace the uid cannot read would make the kernel refuse the whole
        policy at launch (the path must be opened to be bound), which is right but unhelpful."""
        if not self.unique_uid:
            return
        rd, wr = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(rd)
                os.setgroups([])
                os.setgid(self.gid)
                os.setuid(self.uid)
                ok = os.access(self.workspace, os.R_OK | os.X_OK)
                w = os.access(self.workspace, os.W_OK)
                code = any(os.access(p, os.W_OK) for p in (PKG_PARENT, os.path.join(PKG_PARENT, "sharness_ai")))
                os.write(wr, b"c" if code else b"rw" if ok and w else b"r" if ok else b"-")
            finally:
                os._exit(0)
        os.close(wr)
        got = os.read(rd, 8)
        os.close(rd)
        os.waitpid(pid, 0)
        if got == b"c" or PKG_PARENT == self.workspace or PKG_PARENT.startswith(self.workspace.rstrip("/") + "/"):
            raise LaunchError(f"the shell's uid could change the code that confines it ({PKG_PARENT}): it is writable by uid {self.uid} or inside the workspace. "
                              f"Install sharness-ai outside the workspace, in a place only root writes (security review 2, SR-31)")
        if got == b"-":
            raise LaunchError(f"uid {self.uid} ({self.username}) cannot enter {self.workspace}: a path above it is not readable by others. "
                              f"Give the workspace to the shell (chmod o+rx on the path, or a workspace under /tmp), or --no-user to run as this uid (a Setting)")
        if got == b"r":
            raise LaunchError(f"uid {self.uid} ({self.username}) can read but not write {self.workspace}; the shell's profile writes its workspace. "
                              f"chmod o+w {self.workspace}, choose a writable one, or --no-user")

    def stop_processes(self) -> int:
        """Every process of the shell's uid, stopped: a background job does not outlive the session (SR-30).
        Only for a uid made for this shell; as this uid (a Setting) nothing is killed. kill(-1) from the uid
        itself reaches all of its processes and nothing else; repeated until none answers, so a fork
        during the sweep is caught on the next pass."""
        if not (self.unique_uid and self.username):
            return 0
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(self.gid)
                os.setuid(self.uid)
                for _ in range(200):
                    os.kill(-1, signal.SIGKILL)
            except ProcessLookupError:
                os._exit(0)
            except BaseException:  # noqa: BLE001 - the child must not return
                os._exit(1)
            os._exit(2)
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status)

    def remove_user(self):
        code = self.stop_processes()
        left = [x["pid"] for x in processes(self.uid) if x["state"] != "Z"] if code else []   # a zombie waits on its parent, harmless
        if left:
            self.cleanup = f"processes of uid {self.uid} remain: {left[:8]}"
        if self.username and not self.keep_user:
            r = subprocess.run(["userdel", self.username], capture_output=True, text=True)  # noqa: S603,S607
            if r.returncode:
                self.cleanup = (self.cleanup + "; " if self.cleanup else "") + f"userdel {self.username} failed: {r.stderr.strip()}"
            if self.home:
                shutil.rmtree(self.home, ignore_errors=True)

    # ---- start, run, stop ---------------------------------------------------------------------------
    def start(self) -> dict:
        self.session_dir = self.session_dir or tempfile.mkdtemp(prefix="sharness-session-")
        self.session = Session.new(self.session_dir, ROLES)
        self.make_user()
        try:
            self.check_access()
        except LaunchError:
            self.remove_user()
            raise
        policy = {"pbp": 1, "id": "sharness.net", "layer": "component", "hosts": self.sites, "ports": [443, 80]}
        self.net = NET(self.session, policy=policy, allowed_uid=self.uid if self.unique_uid else None)
        door_port, proxy_port = self.net.start()
        self.compile(proxy_port)
        state = {"uid": self.uid, "proxy_port": proxy_port, "hosts": self.sites, "workspace": self.workspace, "door_port": door_port}
        url = None
        if self.want_ui:
            self.ui = UI(state, [self.net.audit], uid=self.uid if self.unique_uid else None)
            url = self.ui.serve()
        return {"session": self.session.id, "uid": self.uid, "user": self.username, "door_port": door_port, "proxy_port": proxy_port,
                "ui": url, "policy_hash": self.chain.at(2).hash, "sentence_hash": self.chain.top.hash, "v0": self.v0}

    def env(self, proxy_port: int) -> dict:
        proxy = f"http://127.0.0.1:{proxy_port}"
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM": os.environ.get("TERM", "xterm"),
               "LANG": os.environ.get("LANG", "C.UTF-8"), "HOME": self.home or os.environ.get("HOME", "/"), "USER": self.username or os.environ.get("USER", ""),
               "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy, "NO_PROXY": "", "no_proxy": "",
               "SHARNESS_AI_SHELL": "1", "SHARNESS_AI_PROXY": proxy, "PS1": r"[sharness \u@\h \W]\$ "}
        return env

    def run_shell(self, argv: list, proxy_port: int) -> int:
        """Fork; the child becomes the uid, gets the clean environment and execs `sharness-ai run`
        with the compiled policy; the kernel is told before the shell starts."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", prefix="sharness-shell-", delete=False) as f:
            json.dump(self.v0, f)
            pp = f.name
        os.chmod(pp, 0o644)
        parent_end, child_end = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            try:
                parent_end.close()
                os.chdir(self.workspace)
                Netns.enter()                                   # no route but loopback; refused if it cannot be made
                with Netns.listen(proxy_port) as s:             # the policy's one port, inside the namespace
                    socket.send_fds(child_end, [b"ok"], [s.fileno()])
                child_end.close()
                if self.unique_uid:
                    os.setgroups([])
                    os.setgid(self.gid)
                    os.setuid(self.uid)
                env = self.env(proxy_port)
                env["PYTHONPATH"] = PKG_PARENT
                cmd = [sys.executable, "-P", "-s", "-m", "sharness_ai", "run", "--policy", pp, "--quiet", "--", *argv]
                os.execve(sys.executable, cmd, env)  # noqa: S606 - a fixed argv, this interpreter, a clean environment; the shell is the job
            except BaseException as e:  # noqa: BLE001
                os.write(2, f"sharness-ai shell: could not start: {e}\n".encode())
            finally:
                os._exit(126)
        child_end.close()
        try:
            parent_end.settimeout(30)
            _, fds, _, _ = socket.recv_fds(parent_end, 16, 1)
        except OSError:
            fds = []
        parent_end.close()
        if fds:                                             # the child said why on stderr when there is none
            uid = self.uid if self.unique_uid else None
            self.inner = Proxy(self.net.rows, self.net.audit, allowed_uid=uid, table=f"/proc/{pid}/net/tcp")
            self.inner.serve(background=True, sock=socket.socket(fileno=fds[0]))
        _, status = os.waitpid(pid, 0)
        try:
            os.unlink(pp)
        except OSError:
            pass
        return os.waitstatus_to_exitcode(status)

    def stop(self) -> dict:
        lines = self.net.audit.dump() if self.net else []
        if self.ui:
            self.ui.stop()
        if self.inner:
            self.inner.stop()
        if self.net:
            self.net.stop()
        self.remove_user()
        return {"cleanup": self.cleanup, "requests": len(lines), "allowed": sum(1 for x in lines if x["allowed"]), "refused": sum(1 for x in lines if not x["allowed"] and x["status"]),
                "hosts": sorted({x["path"].split(":")[0] for x in lines if x["allowed"] and x["method"] in ("CONNECT", "GET", "POST")})}
