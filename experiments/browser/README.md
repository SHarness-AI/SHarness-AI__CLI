# E09: the harness under a second kernel, in Node, in a browser tab, and through chroot

One guest, three ways to run it. The guest is Alpine 3.23 for 32-bit x86: busybox, musl,
Python 3.12 and Alpine's `linux-virt` kernel (6.18, built with Landlock), plus the
`sharness_ai` package from this checkout and the [example policies](../policies/). Nothing in it
is a SHarness component; it is the test bench that lets anyone, with nothing installed, watch
`sharness-ai hello` hold on a real kernel.

| Form | Kernel | CPU | Needs | Command |
|---|---|---|---|---|
| **Node** | the guest's: Linux 6.18.58 i686 | emulated by [v86](https://github.com/copy/v86) (x86 in WebAssembly) | Node 18+, the pinned `v86` package | `npm run node` |
| **browser** | the guest's | emulated by v86, in the tab | a browser; Playwright for the headless run | `npm run browser`, or open `out/www/index.html` over HTTP |
| **chroot** | the **host's**, through the i386 syscall table | the real one | Linux, root | `sudo npm run native` |

The first two show the same syscalls on a second, emulated kernel; the third shows that the
guest's 32-bit binaries drive the host's Landlock through the i386 syscall numbers (444 to
446 there too). All three are *one process confining its child*: a Boundary for the child, a
Setting for whoever ran it. The write-up, with the options not taken and what a browser can
never show, is [sharness.ai/code/browser](https://sharness.ai/code/browser/index.html).

## Build

```
cd experiments/browser
npm ci                                  # v86 0.5.472, pinned; the only dependency, and only here
python3 build_guest.py                  # fetches ~45 MB of Alpine packages once, into cache/
```

`build_guest.py` is standard library only. It unpacks the pinned packages with `tarfile`,
adds `sharness_ai`, the policies and [`init.sh`](init.sh) as `/init`, packs a gzipped newc
cpio with its own writer (no `cpio` binary needed), and assembles `out/www/`: the kernel, the
initramfs, `libv86.mjs`, `v86.wasm`, the two BIOS images and [`page.html`](page.html). A
rebuild from the cache takes seconds. The guest is reproducible: packages and v86 are pinned
by version, the cpio has fixed inode numbers and a zero gzip timestamp.

## Run

```
npm run node                            # boot_node.mjs: v86 in Node, serial console to stdout, exit 0 when hello held
npm run browser                         # boot_browser.mjs: serves out/www, drives headless Chromium with Playwright
sudo npm run native                     # chroot_native.sh: the same binaries on the host kernel
```

`boot_browser.mjs` finds Playwright as a bare module or at `$PLAYWRIGHT`; it is not a
dependency of this repository. The static server it starts sends no COOP or COEP headers on
purpose, and the page reports `crossOriginIsolated` and whether `SharedArrayBuffer` exists, to
record that v86 needs neither. Serial output is decoded as UTF-8 one byte at a time (the
`✔` in `hello`'s output is three bytes).

What [`init.sh`](init.sh) runs, in order: `dmesg | grep landlock`, E01 `probe`, E04 `hello`,
E03 `run` under `p1-agent-session` (port 443 allowed, 80 refused) and `p2-tool-server` (write
refused, read allowed), E02 shape and hash of every example policy in one interpreter, then
`run` under `p0-hello-world` (the 64 MiB cap) and `p2-tool-server` (no write to the workspace).
It ends with `SHARNESS-DONE` and powers the guest off. The runners exit 0 only when
`SHARNESS-HELLO-EXIT 0` was seen.

## Measured, 25 Oct 2026

Environment: one Claude Code cloud session (Ubuntu 24.04, Linux 6.18.44 x86_64, uid 0), Node
22.22, Chromium 153 headless through Playwright, v86 0.5.472, guest Alpine 3.23 x86 with
`linux-virt` 6.18.58-0-virt and Python 3.12.15. Each form run once, alone.

| Form | Guest reports | `hello` | E03 under P1 and P2 | Wall clock to `hello`'s exit / to power-off |
|---|---|---|---|---|
| Node | `landlock: Up and running.`; Landlock ABI 7; `memfd_secret` yes; cgroups v2 | 6 of 6 held | 443 `ENETUNREACH` (allowed by the policy; the guest has no network backend), 80 `EACCES`; write refused, read allowed | 58.0 s / 74.6 s |
| browser | the same | 6 of 6 held | the same | 75.9 s / 95.9 s; `crossOriginIsolated false`, no page errors |
| chroot | host kernel 6.18.44, Landlock ABI 7, guest binaries `e_machine 0x0003` (i386) | 6 of 6 held | not run in this form | under 2 s |

Timings are of an emulated single core and say nothing about the harness's cost; they are here
so a reader knows what to expect of the page. The guest's `cgroups v2` line is the guest's own
`/sys/fs/cgroup`; the chroot form reports `cgroups unknown` because it mounts only `/proc`.

Found on the way: under `allow-https-example` (exec `/usr` and `/bin` only) the guest could not
start `python3` at all, with `Permission denied` from `execve`. Alpine's ELF interpreter is
`/lib/ld-musl-i386.so.1`, and Landlock's execute right must cover the interpreter as well as the
binary. On the host, a merged `/usr` hides this (`/lib64` is a link into `/usr`). The profiles
P0 to P4 list `/lib` and `/lib64` as executable for that reason; the two older examples keep
their paths, and their hashes.

## Not here

A network backend for the guest (v86 can proxy over `fetch` or WebSocket), so a connect on port
443 would succeed without a policy and fail with `EACCES` under one. A booted-state snapshot so
the page opens in seconds rather than after a full boot. A non-root user in the guest, so the
network probe takes Landlock's port rule rather than the namespace. A kernel without Landlock as
the negative control. `memfd_secret`'s 32-bit caveat is untested (it is probed, not used).
