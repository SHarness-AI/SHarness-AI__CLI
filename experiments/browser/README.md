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

## The playground: type `sharness-ai` into either runtime

`out/www/playground.html` (source: [`playground.html`](playground.html) and
[`playground.js`](playground.js), one ES module, no framework) puts two terminals side by side:

| Tab | What it is | What works there |
|---|---|---|
| **Pyodide** | CPython 3.14 compiled to WebAssembly (Pyodide 314.0.7 from jsDelivr); `pip install sharness-ai` installs the dev wheel from the same folder with `micropip` | `policy hash`, `check`, `translate`, `probe` (which says there is no kernel); `run` and `hello` refuse with exit 126: no kernel, no processes, nothing to confine |
| **Linux** | the guest above booted with `sharness.mode=shell` on the kernel command line, so `/init` gives a shell on the serial line instead of the scripted run | everything, enforced by the guest kernel: `probe`, `hello`, `run` under any policy |

A policy panel hashes the same JSON three ways (the browser's WebCrypto, the CLI in Pyodide, the
CLI in the guest) and shows whether they agree; "Use it" copies the edited policy into both
runtimes as `policies/my-policy.json` (into the guest as base64 over the serial line, the only
way in). [`build_wheel.py`](build_wheel.py) builds the wheel with the standard library and
names it `<version>+dev.<commit>`, so it can never be mistaken for a PyPI release.
`node test_playground.mjs` drives both tabs in headless Chromium and checks eleven things.

## The network backend and the interceptor

The guest has a network card (virtio-net; the driver is unpacked from Alpine's kernel package into
the initramfs) and v86's **fetch backend** behind it: the page answers as the router, the DHCP
server and the DNS of a fake subnet, and turns every HTTP request the guest makes on port 80 into
the browser's own `fetch()`. Other ports are refused with a TCP reset: there is no TLS passthrough,
the page is the TLS client. That is the shape of `sharness.net` in the design, done by the page.

[`netwatch.js`](netwatch.js) is the interceptor, in the playground under the Linux terminal: every
frame the guest sends or receives is decoded (ARP, DHCP, DNS with record types, ICMP, TCP flags,
HTTP request and status lines) into a table of flows with a detail pane (headers both ways, every
event with its time). It also wraps the backend's `fetch` with an **egress allowlist of hostnames**,
enforced outside the guest by code the guest cannot reach: a Boundary for everything inside, root
included. A host not on the list gets a 403 from the page before any `fetch()` happens. Three
verdicts appear in one session, and the test checks all three:

| What the guest did | Where it was decided | What the panel shows |
|---|---|---|
| `wget http://sharness.ai/llms.txt`, no policy | the page: on the allowlist | DNS, TCP :80, `HTTP GET … allowed 200` |
| `wget http://example.com/` | the page: not on the allowlist | `HTTP GET … blocked`, the guest sees 403 |
| the same under P1 (TCP 443 only) | the **kernel**, before any packet left the process | no TCP or HTTP row at all; the DNS query still appears, because Landlock does not see UDP |
| the same under P5 (80 and 443) | the kernel allows, the page allows | the flow, with 200 |

Limits, on the panel itself: a host that sends no CORS header fails in the browser (the guest sees
502); only HTTP on port 80 is served; the guest's view of DNS is the page's static answer, a fake
address the page maps back to the name. In Node, `boot_node.mjs` runs the same guest with Node's
`fetch()`; behind a proxy set `NODE_USE_ENV_PROXY=1`.

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
npm run playground                      # test_playground.mjs: both playground tabs, end to end (needs jsDelivr for Pyodide)
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

Playground, measured 25 Oct 2026 (the same session, headless Chromium 153, served from
`out/www`): Pyodide loaded in about 3 s and installed the wheel in under 1 s; the guest
reached its shell prompt in about 40 s; `hello` held 6 of 6 there, P2 refused a write, and
the three hashes of P0 were identical; 11 of 11 checks, no page errors, about 85 s in all.

## Not here

A booted-state snapshot so
the page opens in seconds rather than after a full boot. A non-root user in the guest, so the
network probe takes Landlock's port rule rather than the namespace. TLS from inside the guest (the page would have to be a trusted CA to the guest, or relay raw TCP over a WebSocket to a server, which is a different trust model). A kernel without Landlock as
the negative control. `memfd_secret`'s 32-bit caveat is untested (it is probed, not used).

## The first door inside the guest (E11)

The scripted run ends with the door: `sharness-ai session new` (the guest carries `openssl`), `sharness-ai fs serve
--target disk.twin` on loopback (`ifconfig lo up` in `init.sh`), `fs hello` over mutual TLS, a write allowed, a
private key refused. Measured 26 Oct 2026 in Node (v86, one emulated core): the whole scripted run 194.8 s wall
clock, of which the door's five commands about 40 s; `hello` 6 of 6 as before. The playground's Linux tab has
chips for the same commands.
