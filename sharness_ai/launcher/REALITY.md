# REALITY: sharness.launcher, 26 Oct 2026

- `Launcher.py`: `start()` (a session with app, fs, net, launcher; the uid; the net door for that uid; the policy compiled
  from the sentence with the proxy's port as the only network row; the live page), `run_shell(argv, proxy_port)` (fork,
  setgid/setuid, a clean environment with HTTPS_PROXY, exec `sharness-ai run --policy …`), `stop()` (the counts; the user
  removed; the doors stopped).
- `Watch.py`: `processes(uid)` from /proc. `UI.py`: one page and a server-sent event stream on loopback under a token.

Not here: the fs door for the workspace (the shell writes it directly, which the kernel bounds to the workspace); a pid
or network namespace for the shell; the doors under their own policies and uids; the mirror-rule check on edges; kernel
refusals on the page (Landlock audit); a `manifest` document (the plan is computed, not read). Dependency exceptions
taken: none (useradd, userdel and openssl are programs on the machine).
