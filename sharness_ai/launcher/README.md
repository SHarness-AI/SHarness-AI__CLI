# sharness.launcher, the first slice: a shell under the harness

`sharness-ai shell --workspace . --sites github.com pypi.org` gives an interactive shell where:

- the kernel holds the files (the workspace writable, the system read-only), the caps and **one port**: the proxy's;
- `sharness.net.proxy` holds the hosts: every connection the shell makes is a CONNECT or an HTTP request the door
  decided, logged with its verdict; an IP literal, a host off the list, a tunnel whose TLS hello names another host
  are refused; the proxy answers the shell's uid and no other;
- where the launcher is root, the shell runs as a **unique system uid** created for it (removed on exit unless
  `--keep-user`), with a fresh home; otherwise it runs as the launcher's uid, and that is a Setting;
- a **live page** on loopback (a random token in its address) shows the traffic, the shell's processes and every
  refusal with who made it, as they happen.

The sentence (level 5) is compiled as `contain` does; the level-2 step replaces the sites' ports with the proxy's
port, so the host names that `contain` reports as unheld are **held here, by sharness.net**.

**Status: runnable, proposed (26 Oct 2026).** This is the launcher for one shell, not the launcher of the design:
the doors run as the launcher's own children, no edge's contract is checked by hash, no other door is started under
its own policy. Kernel refusals (EACCES) are not yet on the live page: Landlock's audit (ABI 7) is the next step.
DNS: a shell that resolves names itself speaks UDP the kernel does not see; clients that honour `HTTPS_PROXY` send
the name to the proxy and resolve nothing. Standard library only; `useradd` and `userdel` are programs on the machine.
