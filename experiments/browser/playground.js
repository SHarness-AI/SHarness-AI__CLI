// SHarness playground: sharness-ai in two runtimes on one page.
//
//   Pyodide  Python compiled to WebAssembly. `pip install` the dev wheel from this site with
//            micropip, then hash, check and translate policies. No kernel: run and hello refuse.
//   Linux    the E09 guest (Alpine x86, Linux 6.18 with Landlock) booted by v86 in this tab,
//            with a shell on its serial line: every command, enforced by a real kernel.
//
// Mount: <div id="sharness-playground" data-assets="./"></div> and load this module.
// data-assets is where the kernel, initramfs, v86, the wheel and the policies are served.
// Test hook: window.sharnessPlayground = { pyRun, linuxRun, bootLinux, hashEverywhere, state }.

const ROOT = document.getElementById("sharness-playground");
const ASSETS = new URL(ROOT.dataset.assets || "./", location.href).href;
const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";
const POLICIES = ["p0-hello-world", "p1-agent-session", "p2-tool-server", "p3-newsroom-agent", "p4-sgit",
                  "deny-all-example", "allow-https-example"];
const PROMPT = /sharness:\/work# /g;
const CSI = /\x1b\[[0-9;?]*[A-Za-z]/g;
import { attachNetwatch } from "./netwatch.js";

const CHIPS = {
  py: [
    ["pip install sharness-ai", "install the dev wheel from this site"],
    ["sharness-ai --version", ""],
    ["sharness-ai policy check policies/p1-agent-session.json", "the shape of a v0 policy"],
    ["sharness-ai policy hash policies/p1-agent-session.json", "the one value the person supplies"],
    ["sharness-ai policy translate policies/p1-agent-session.json --to claude-code", "the same policy as Claude Code settings, and the gap"],
    ["sharness-ai policy translate policies/p2-tool-server.json --to docker -- my-tool", "as docker run"],
    ["sharness-ai probe", "the grant here: no kernel"],
    ["sharness-ai hello", "refuses: nothing to confine"],
    ["sharness-ai guide --once", "where you are, the ladder, what next"],
    ["sharness-ai policy new my-tool.json -y --write /work/out --ports 443", "five answers write a policy; its hash is its name"],
    ["sharness-ai policy show my-tool.json", "one process, its edges, its hash"],
    ["sharness-ai components", "the OS a process sees: designed, not built"],
  ],
  linux: [
    ["sharness-ai guide --once", "where you are, the ladder, what next"],
    ["sharness-ai probe", "the grant: root, Landlock ABI 7"],
    ["sharness-ai hello", "the acceptance test, 6 probes"],
    ["sharness-ai policy show policies/p2-tool-server.json", "one process, its edges, its hash"],
    ["cat policies/p2-tool-server.json", ""],
    ["sharness-ai run --policy policies/p2-tool-server.json -- sh -c 'echo hi > /work/x.txt'", "write refused"],
    ["sharness-ai run --policy policies/p1-agent-session.json -- python3 -c \"import socket; socket.create_connection(('1.1.1.1', 80))\"", "port 80 refused"],
    ["sharness-ai run --policy policies/p0-hello-world.json -- python3 -c \"bytearray(200 << 20)\"", "200 MiB over a 64 MiB cap"],
    ["sharness-ai run --policy policies/p0-hello-world.json -- sh -c 'echo $SHARNESS_AI_POLICY_HASH'", "the child knows its policy"],
    ["sharness-ai run --expect-hash sha256:0000 --policy policies/p0-hello-world.json -- true", "wrong hash: nothing runs"],
    ["wget -q -O - http://sharness.ai/llms.txt | head -3", "through the page's fetch(), on the allowlist"],
    ["wget -q -O - http://example.com/ | head -3", "not on the allowlist: 403 from the page"],
    ["sharness-ai run --policy policies/p5-web-fetch.json -- wget -q -O - http://sharness.ai/llms.txt | head -1", "P5 allows 80: the request appears below"],
    ["sharness-ai run --policy policies/p1-agent-session.json -- wget -q -O - -T 3 http://sharness.ai/llms.txt", "P1 allows 443 only: refused by the kernel, nothing below"],
    ["wget -q -O - -T 5 https://sharness.ai/llms.txt", "port 443: refused by the page, which serves only HTTP"],
    ["dmesg | grep -i landlock", ""],
  ],
};

// ---- canonical JSON and SHA-256, the same bytes as sharness_ai/policy.py ------------------
function canon(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isInteger(v)) throw new Error("floats are not allowed in a policy"); return String(v); }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
async function jsHash(text) {
  const bytes = new TextEncoder().encode(canon(JSON.parse(text)));
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return "sha256:" + [...d].map(b => b.toString(16).padStart(2, "0")).join("");
}

// ---- styles (scoped; the site's variables when present) -----------------------------------
const css = `
#sharness-playground{--pg-bg:#0d1117;--pg-fg:#e6edf3;--pg-dim:#8b949e;--pg-green:#3fb950;--pg-red:#f85149;--pg-yellow:#d29922;--pg-blue:#58a6ff;--pg-line:#30363d;margin:1.2rem 0}
#sharness-playground *{box-sizing:border-box}
.pg-tabs{display:flex;gap:.4rem;flex-wrap:wrap;margin-bottom:.6rem}
.pg-tab{font:600 .86rem/1.2 var(--sans,system-ui);padding:.55rem .9rem;border-radius:8px;border:1px solid var(--line2,#d0d7de);background:var(--panel,#f6f8fa);color:var(--fg,#1f2328);cursor:pointer;text-align:left}
.pg-tab small{display:block;font-weight:400;opacity:.75;margin-top:.15rem}
.pg-tab[aria-selected=true]{background:var(--pg-bg);color:var(--pg-fg);border-color:var(--pg-bg)}
.pg-grid{display:grid;grid-template-columns:1fr;gap:1rem}
@media(min-width:980px){.pg-grid{grid-template-columns:minmax(0,1.7fr) minmax(0,1fr)}}
.pg-term[hidden]{display:none}
.pg-term{background:var(--pg-bg);color:var(--pg-fg);border-radius:10px;overflow:hidden;display:flex;flex-direction:column;min-height:540px}
.pg-bar{display:flex;align-items:center;gap:.6rem;padding:.45rem .8rem;border-bottom:1px solid var(--pg-line);font:.78rem/1.3 var(--mono,ui-monospace,monospace);color:var(--pg-dim)}
.pg-dot{width:.6rem;height:.6rem;border-radius:50%;background:var(--pg-dim);flex:none}
.pg-dot.ready{background:var(--pg-green)} .pg-dot.busy{background:var(--pg-yellow);animation:pgp 1s infinite} .pg-dot.err{background:var(--pg-red)}
@keyframes pgp{50%{opacity:.3}}
.pg-bar .pg-status{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pg-bar button{font:600 .75rem var(--sans,system-ui);border:1px solid var(--pg-line);background:#161b22;color:var(--pg-fg);border-radius:6px;padding:.25rem .6rem;cursor:pointer}
.pg-bar button.go{background:#238636;border-color:#238636}
.pg-out{flex:1;overflow:auto;padding:.7rem .9rem;font:.8rem/1.45 var(--mono,ui-monospace,monospace);white-space:pre-wrap;word-break:break-word;max-height:62vh;min-height:360px}
.pg-out .c{color:var(--pg-blue)} .pg-out .d{color:var(--pg-dim)} .pg-out .g{color:var(--pg-green)} .pg-out .r{color:var(--pg-red)} .pg-out .y{color:var(--pg-yellow)}
.pg-chips{display:flex;gap:.35rem;flex-wrap:nowrap;overflow-x:auto;scrollbar-width:thin;padding:.5rem .8rem;border-top:1px solid var(--pg-line)}
.pg-chip{flex:none;font:.72rem/1.2 var(--mono,ui-monospace,monospace);border:1px solid var(--pg-line);background:#161b22;color:var(--pg-fg);border-radius:999px;padding:.25rem .6rem;cursor:pointer;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pg-chip:hover{border-color:var(--pg-blue)}
.pg-in{display:flex;align-items:center;gap:.5rem;padding:.55rem .9rem;border-top:1px solid var(--pg-line);font:.82rem var(--mono,ui-monospace,monospace)}
.pg-in span{color:var(--pg-green);white-space:nowrap}
.pg-in input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:var(--pg-fg);font:inherit}
.pg-side{display:flex;flex-direction:column;gap:.6rem}
.pg-side label{font:600 .8rem var(--sans,system-ui)}
.pg-side select,.pg-side textarea{width:100%;font:.76rem/1.4 var(--mono,ui-monospace,monospace);padding:.5rem .6rem;border:1px solid var(--line2,#d0d7de);border-radius:8px;background:var(--panel,#fff);color:var(--fg,#1f2328)}
.pg-side textarea{min-height:250px;resize:vertical}
.pg-btns{display:flex;gap:.4rem;flex-wrap:wrap}
.pg-btns button{font:600 .78rem var(--sans,system-ui);padding:.4rem .7rem;border-radius:6px;border:1px solid var(--line2,#d0d7de);background:var(--panel,#f6f8fa);color:var(--fg,#1f2328);cursor:pointer}
.pg-btns button.primary{background:var(--accent-dk,#1f6feb);border-color:var(--accent-dk,#1f6feb);color:#fff}
.pg-hashes{font:.74rem/1.5 var(--mono,ui-monospace,monospace);border:1px solid var(--line2,#d0d7de);border-radius:8px;padding:.5rem .7rem;background:var(--panel,#f6f8fa);overflow-wrap:anywhere}
.pg-hashes .ok{color:#1a7f37} .pg-hashes .bad{color:#cf222e}
.pg-note{font:.78rem/1.45 var(--sans,system-ui);color:var(--dim,#59636e)}
.nw{margin-top:.8rem;background:var(--panel,#fff);border:1px solid var(--line2,#d0d7de);border-radius:10px;overflow:hidden}
.nw-bar{display:flex;align-items:center;gap:.8rem;flex-wrap:wrap;padding:.5rem .8rem;border-bottom:1px solid var(--line2,#d0d7de);font:.8rem var(--sans,system-ui);color:var(--fg,#1f2328)}
.nw-bar b{font-size:.84rem}.nw-n{color:var(--dim,#59636e)}
.nw-bar label{display:inline-flex;align-items:center;gap:.35rem}
.nw-bar input[type=text]{font:.76rem var(--mono,ui-monospace,monospace);padding:.25rem .5rem;border:1px solid var(--line2,#d0d7de);border-radius:6px;min-width:14rem;background:var(--panel,#fff);color:var(--fg,#1f2328)}
.nw-bar button{font:600 .74rem var(--sans,system-ui);border:1px solid var(--line2,#d0d7de);background:var(--panel,#f6f8fa);color:var(--fg,#1f2328);border-radius:6px;padding:.25rem .6rem;cursor:pointer;margin-left:auto}
.nw-table{max-height:260px;overflow:auto}
.nw table{width:100%;border-collapse:collapse;font:.74rem/1.4 var(--mono,ui-monospace,monospace)}
.nw th{position:sticky;top:0;background:var(--panel2,#f6f8fa);text-align:left;padding:.35rem .6rem;font:600 .66rem var(--sans,system-ui);letter-spacing:.08em;text-transform:uppercase;color:var(--dim,#59636e)}
.nw td{padding:.3rem .6rem;border-top:1px solid var(--line,#eaeef2);vertical-align:top;color:var(--fg,#1f2328);max-width:28rem;overflow-wrap:anywhere}
.nw td:first-child,.nw td:nth-child(2){white-space:nowrap}
.nw tr{cursor:pointer}.nw tr:hover td{background:var(--panel2,#f6f8fa)}
.nw .v{font:600 .68rem var(--sans,system-ui);border-radius:999px;padding:.1rem .5rem;white-space:nowrap}
.nw .v.allowed{background:#dafbe1;color:#116329}.nw .v.blocked{background:#ffebe9;color:#a40e26}.nw .v.refused{background:#fff8c5;color:#7d4e00}
.nw-detail{margin:0;padding:.6rem .8rem;border-top:1px solid var(--line2,#d0d7de);background:#0d1117;color:#e6edf3;font:.74rem/1.5 var(--mono,ui-monospace,monospace);white-space:pre-wrap;max-height:220px;overflow:auto}
.nw-note{margin:0;padding:.5rem .8rem;font:.74rem/1.45 var(--sans,system-ui);color:var(--dim,#59636e);border-top:1px solid var(--line,#eaeef2)}
`;
document.head.append(Object.assign(document.createElement("style"), { textContent: css }));

// ---- DOM -----------------------------------------------------------------------------------
ROOT.innerHTML = `
<div class="pg-tabs" role="tablist">
  <button class="pg-tab" role="tab" data-mode="py" aria-selected="true">Pyodide: Python in WebAssembly<small>pip install, then hash, check, translate. No kernel.</small></button>
  <button class="pg-tab" role="tab" data-mode="linux" aria-selected="false">Linux: a real kernel with Landlock<small>Alpine in v86. run and hello, enforced.</small></button>
</div>
<div class="pg-grid">
  <div>
    ${["py", "linux"].map(m => `
    <div class="pg-term" data-term="${m}" ${m === "linux" ? "hidden" : ""}>
      <div class="pg-bar"><span class="pg-dot"></span><span class="pg-status"></span>
        ${m === "linux" ? '<button type="button" class="go" data-act="boot">Boot Linux (25 MB)</button><button type="button" data-act="ctrlc" title="send Ctrl-C">^C</button>' : '<button type="button" class="go" data-act="start">Start Pyodide</button>'}
        <button type="button" data-act="clear">clear</button></div>
      <div class="pg-out" aria-live="polite"></div>
      <div class="pg-chips"></div>
      <div class="pg-in"><span>${m === "py" ? "pyodide:/work$" : "sharness:/work#"}</span><input type="text" spellcheck="false" autocomplete="off" aria-label="command"></div>
    </div>
    ${m === "linux" ? '<div id="pg-netwatch" hidden></div>' : ""}`).join("")}
  </div>
  <div class="pg-side">
    <label for="pg-pick">A Process Behaviour Policy</label>
    <select id="pg-pick">${POLICIES.map(p => `<option>${p}</option>`).join("")}</select>
    <textarea id="pg-policy" spellcheck="false" aria-label="policy JSON"></textarea>
    <div class="pg-btns">
      <button type="button" class="primary" data-act="hash3">Hash it in three places</button>
      <button type="button" data-act="use">Use it: policies/my-policy.json</button>
    </div>
    <div class="pg-hashes" id="pg-hashes">The browser's WebCrypto, the CLI in Pyodide and the CLI in the Linux guest each hash this policy. A launcher would compare one of them with the hash the person supplied.</div>
    <p class="pg-note">Edit the JSON and hash again: one character changes the hash. "Use it" writes the file into both runtimes, so <code>sharness-ai run --policy policies/my-policy.json -- …</code> runs under your policy in Linux.</p>
  </div>
</div>`;

const $ = (sel, el = ROOT) => el.querySelector(sel);
const T = {};
for (const m of ["py", "linux"]) {
  const box = $(`[data-term=${m}]`);
  T[m] = { box, out: $(".pg-out", box), dot: $(".pg-dot", box), status: $(".pg-status", box), input: $("input", box), hist: [], hi: 0 };
  const chips = $(".pg-chips", box);
  for (const [cmd, tip] of CHIPS[m]) {
    const b = Object.assign(document.createElement("button"), { type: "button", className: "pg-chip", textContent: cmd, title: tip || cmd });
    b.onclick = () => submit(m, cmd);
    chips.append(b);
  }
  T[m].input.addEventListener("keydown", (e) => {
    const t = T[m];
    if (e.key === "Enter") { const v = t.input.value; t.input.value = ""; submit(m, v); }
    else if (e.key === "ArrowUp" && t.hist.length) { t.hi = Math.max(0, t.hi - 1); t.input.value = t.hist[t.hi]; e.preventDefault(); }
    else if (e.key === "ArrowDown" && t.hist.length) { t.hi = Math.min(t.hist.length, t.hi + 1); t.input.value = t.hist[t.hi] || ""; e.preventDefault(); }
    else if (m === "linux" && e.ctrlKey && e.key === "c" && !t.input.value) { linux.emulator?.serial0_send("\x03"); }
  });
}
function write(m, text, cls) {
  const o = T[m].out, stick = o.scrollTop + o.clientHeight >= o.scrollHeight - 30;
  const s = document.createElement("span"); if (cls) s.className = cls; s.textContent = text; o.append(s);
  if (stick) o.scrollTop = o.scrollHeight;
}
function status(m, text, kind) { T[m].status.textContent = text; T[m].dot.className = "pg-dot " + (kind || ""); }
function tab(m) {
  for (const b of ROOT.querySelectorAll(".pg-tab")) b.setAttribute("aria-selected", String(b.dataset.mode === m));
  for (const k of ["py", "linux"]) T[k].box.hidden = k !== m;
}
for (const b of ROOT.querySelectorAll(".pg-tab")) b.onclick = () => tab(b.dataset.mode);
ROOT.addEventListener("click", (e) => {
  const act = e.target.closest("[data-act]")?.dataset.act;
  if (act === "start") startPy();
  if (act === "boot") bootLinux();
  if (act === "ctrlc") linux.emulator?.serial0_send("\x03");
  if (act === "clear") { const m = e.target.closest("[data-term]").dataset.term; T[m].out.textContent = ""; if (m === "linux") T.linux.out.append(linux.live = document.createTextNode("")); }
  if (act === "hash3") hashEverywhere();
  if (act === "use") usePolicy();
});
function submit(m, line) {
  line = line.trim();
  const t = T[m];
  if (line) { t.hist.push(line); t.hi = t.hist.length; }
  if (m === "py") return pyRun(line, true);
  if (!linux.emulator) { write("linux", "Boot Linux first (the button above).\n", "y"); return; }
  return linuxRun(line);
}

// ---- Pyodide ------------------------------------------------------------------------------
const py = { pyodide: null, ready: false, installed: false, loading: null, wheel: null };
const PY_SH = `
import io, contextlib, shlex, os
def sh(line):
    out = io.StringIO()
    from sharness_ai.cli import main
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        try:
            code = main(shlex.split(line)[1:])
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        except BaseException as e:
            print(f"{type(e).__name__}: {e}"); code = 1
    return out.getvalue(), code or 0
def hash_text(text):
    import json
    from sharness_ai.policy import policy_hash
    return policy_hash(json.loads(text))
`;
async function startPy() {
  if (py.loading) return py.loading;
  return (py.loading = (async () => {
    status("py", "loading Pyodide 314 (Python 3.14 in WebAssembly) from cdn.jsdelivr.net …", "busy");
    write("py", "Loading Pyodide: CPython compiled to WebAssembly, no kernel, no processes.\n", "d");
    const t0 = performance.now();
    const { loadPyodide } = await import(PYODIDE + "pyodide.mjs");
    py.pyodide = await loadPyodide({ indexURL: PYODIDE });
    const pyv = py.pyodide.runPython("import sys; sys.version.split()[0]");
    write("py", `Python ${pyv} ready in ${((performance.now() - t0) / 1000).toFixed(1)} s. Next: pip install sharness-ai\n\n`, "d");
    py.pyodide.FS.mkdirTree("/work/policies");
    for (const p of POLICIES) py.pyodide.FS.writeFile(`/work/policies/${p}.json`, await (await fetch(ASSETS + `policies/${p}.json`)).text());
    py.pyodide.runPython("import os; os.chdir('/work')");
    status("py", `Pyodide ${py.pyodide.version} · Python ${pyv} · sharness-ai not installed yet`, "ready");
    $('[data-act=start]', T.py.box).hidden = true;
    py.ready = true;
  })());
}
async function pyInstall() {
  status("py", "installing …", "busy");
  py.wheel = py.wheel || await (await fetch(ASSETS + "wheel.json")).json();
  write("py", `Collecting sharness-ai ${py.wheel.version} (the dev branch, built ${py.wheel.built}; PyPI has the last release)\n`, "d");
  write("py", `  from ${py.wheel.wheel} (${(py.wheel.size / 1024).toFixed(1)} kB, ${py.wheel.sha256.slice(0, 19)}…)\n`, "d");
  await py.pyodide.loadPackage("micropip", { messageCallback: () => {} });
  await py.pyodide.runPythonAsync(`import micropip\nawait micropip.install(${JSON.stringify(ASSETS + py.wheel.wheel)})`);
  py.pyodide.runPython(PY_SH);
  py.installed = true;
  write("py", `Successfully installed sharness-ai-${py.wheel.version}\n`, "g");
  status("py", `Pyodide ${py.pyodide.version} · sharness-ai ${py.wheel.version} installed · the example policies are in policies/`, "ready");
}
async function pyRun(line, echo) {
  const show = echo !== false;
  if (show) write("py", `pyodide:/work$ ${line}\n`, "c");
  if (!line) return "";
  if (line === "clear") { T.py.out.textContent = ""; return ""; }
  await startPy();                       // the whole start-up: Pyodide, the policies, cwd /work
  const words = line.split(/\s+/);
  let out = "", code = 0;
  if (/^pip3? install (sharness-ai|sharness_ai)$/.test(line)) {
    if (py.installed) out = "Requirement already satisfied: sharness-ai\n"; else { await pyInstall(); return ""; }
  } else if (words[0] === "sharness-ai") {
    if (!py.installed) out = "sharness-ai: not installed yet. Run: pip install sharness-ai\n", code = 127;
    else { status("py", "running …", "busy"); [out, code] = py.pyodide.globals.get("sh")(line).toJs(); status("py", `Pyodide ${py.pyodide.version} · sharness-ai ${py.wheel.version} installed`, "ready"); }
  } else if (words[0] === "ls") {
    out = py.pyodide.runPython(`import os; "\\n".join(sorted(os.listdir(${JSON.stringify(words[1] || ".")})))`) + "\n";
  } else if (words[0] === "cat" && words[1]) {
    try { out = py.pyodide.FS.readFile(words[1].startsWith("/") ? words[1] : "/work/" + words[1], { encoding: "utf8" }); } catch { out = `cat: ${words[1]}: No such file\n`; code = 1; }
  } else if (line === "help") {
    out = "This terminal is not a shell: Pyodide has no processes. It knows pip install sharness-ai, sharness-ai …, ls, cat, clear.\nFor a real shell, a kernel and Landlock, use the Linux tab.\n";
  } else { out = `${words[0]}: not here. Pyodide has no shell or processes; try help, or the Linux tab.\n`; code = 127; }
  if (show) { write("py", out.endsWith("\n") || !out ? out : out + "\n", code ? "y" : ""); if (code) write("py", `[exit ${code}]\n`, "d"); }
  return out;
}

// ---- Linux in v86 -------------------------------------------------------------------------
const linux = { emulator: null, text: "", pending: "", live: null, prompts: 0, ready: false, booting: null, waiters: [], quiet: false };
function linuxFeed(chunk) {
  linux.pending += chunk;
  let keep = "";
  const m = linux.pending.match(/\x1b(\[[0-9;?]*)?$/);
  if (m) { keep = m[0]; linux.pending = linux.pending.slice(0, -keep.length); }
  const clean = linux.pending.replace(CSI, "").replace(/\r/g, "");
  linux.pending = keep;
  if (!clean) return;
  linux.text += clean;
  if (!linux.quiet) {                       // housekeeping commands (file transfer) stay off screen
    const o = T.linux.out, stick = o.scrollTop + o.clientHeight >= o.scrollHeight - 30;
    linux.live.appendData(clean);
    if (stick) o.scrollTop = o.scrollHeight;
  }
  const n = (linux.text.match(PROMPT) || []).length;
  if (n !== linux.prompts) { linux.prompts = n; for (const w of linux.waiters.splice(0)) w(); }
}
function nextPrompt() { return new Promise(r => linux.waiters.push(r)); }
async function bootLinux() {
  if (linux.booting) return linux.booting;
  tab("linux");
  return (linux.booting = (async () => {
    $('[data-act=boot]', T.linux.box).hidden = true;
    T.linux.out.append(linux.live = document.createTextNode(""));
    const t0 = performance.now();
    status("linux", "downloading the kernel, the initramfs and v86 (25 MB) …", "busy");
    const { V86 } = await import(ASSETS + "libv86.mjs");
    linux.emulator = new V86({
      wasm_path: ASSETS + "v86.wasm", bios: { url: ASSETS + "seabios.bin" }, vga_bios: { url: ASSETS + "vgabios.bin" },
      bzimage: { url: ASSETS + "vmlinuz-virt" }, initrd: { url: ASSETS + "initramfs.cpio.gz" },
      cmdline: "console=ttyS0,115200 rdinit=/init panic=5 tsc=unstable quiet sharness.mode=shell",
      memory_size: 512 * 1024 * 1024, vga_memory_size: 2 * 1024 * 1024,
      autostart: true, disable_keyboard: true, disable_mouse: true, disable_speaker: true,
      net_device: { type: "virtio", relay_url: "fetch" },     // the guest's card; its packets become this page's fetch()
    });
    const nw = document.getElementById("pg-netwatch"); nw.hidden = false;
    linux.netwatch = attachNetwatch(linux.emulator, { mount: nw, allow: ["sharness.ai"] });
    const dec = new TextDecoder();
    linux.emulator.add_listener("serial0-output-byte", (b) => { const c = dec.decode(new Uint8Array([b]), { stream: true }); if (c) linuxFeed(c); });
    linux.emulator.add_listener("emulator-started", () => status("linux", "booting Linux 6.18 on an emulated i686 …", "busy"));
    const tick = setInterval(() => { if (!linux.ready) status("linux", `booting Linux 6.18 on an emulated i686 … ${((performance.now() - t0) / 1000).toFixed(0)} s`, "busy"); }, 1000);
    await nextPrompt();
    clearInterval(tick);
    linux.ready = true;
    status("linux", `Alpine 3.23 · Linux 6.18.58 i686 · Landlock on · on the page's network · up in ${((performance.now() - t0) / 1000).toFixed(0)} s · each command takes seconds: the CPU is emulated`, "ready");
    T.linux.input.focus();
  })());
}
let linuxQueue = Promise.resolve();
function linuxRun(line, quiet = false) {
  const job = linuxQueue.then(async () => {
    if (!linux.ready) await bootLinux();
    const start = linux.text.length, t0 = performance.now();
    status("linux", quiet ? "copying a file into the guest …" : `running: ${line}`, "busy");
    const done = nextPrompt();
    linux.quiet = quiet;
    linux.emulator.serial0_send(line + "\n");
    await done;
    linux.quiet = false;
    status("linux", `done in ${((performance.now() - t0) / 1000).toFixed(1)} s · Alpine 3.23 · Linux 6.18.58 i686 · Landlock on`, "ready");
    const out = linux.text.slice(start);
    return out.slice(out.indexOf("\n") + 1).replace(/sharness:\/work# $/, "");
  });
  linuxQueue = job.catch(() => {});
  return job;
}
async function linuxWrite(path, text) {
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(text)));
  // the serial line is the only way in: base64 in shell-sized chunks, then decoded in the guest
  await linuxRun(": > /tmp/.in.b64", true);
  for (let i = 0; i < b64.length; i += 600) await linuxRun(`echo ${b64.slice(i, i + 600)} >> /tmp/.in.b64`, true);
  const out = await linuxRun(`base64 -d /tmp/.in.b64 > ${path} && rm /tmp/.in.b64 && echo ok`, true);
  linux.live.appendData(`(copied ${text.length} bytes from the editor to ${path} over the serial line)\nsharness:/work# `);
  return out;
}

// ---- the policy panel ------------------------------------------------------------------------
const pick = $("#pg-pick"), area = $("#pg-policy"), hashes = $("#pg-hashes");
async function loadPolicy() { area.value = await (await fetch(ASSETS + `policies/${pick.value}.json`)).text(); }
pick.onchange = loadPolicy;
async function hashEverywhere() {
  const text = area.value, rows = [];
  hashes.innerHTML = "hashing …";
  try { rows.push(["browser WebCrypto", await jsHash(text)]); } catch (e) { rows.push(["browser WebCrypto", "error: " + e.message]); }
  if (py.installed) { try { rows.push(["sharness-ai in Pyodide", py.pyodide.globals.get("hash_text")(text)]); } catch (e) { rows.push(["sharness-ai in Pyodide", "error: " + String(e).split("\n").pop()]); } }
  else rows.push(["sharness-ai in Pyodide", "not installed: pip install sharness-ai in the Pyodide tab"]);
  if (linux.ready) {
    await linuxWrite("/tmp/hash-check.json", text);
    const out = await linuxRun("sharness-ai policy hash /tmp/hash-check.json");
    rows.push(["sharness-ai in Linux", (out.match(/sha256:[0-9a-f]{64}/) || [out.trim()])[0]]);
  } else rows.push(["sharness-ai in Linux", "not booted: Boot Linux in the Linux tab"]);
  const got = rows.map(r => r[1]).filter(v => v.startsWith("sha256:"));
  const same = got.length > 1 && got.every(v => v === got[0]);
  hashes.replaceChildren(...rows.map(([k, v]) => {            // text nodes only: output from a runtime is data, never markup
    const d = document.createElement("div"), b = document.createElement("b"), s = document.createElement("span");
    b.textContent = k; s.textContent = v;
    if (v.startsWith("sha256:")) s.className = same || got.length === 1 ? "ok" : "bad";
    d.append(b, document.createElement("br"), s);
    return d;
  }), Object.assign(document.createElement("div"), { style: "margin-top:.4rem", className: got.length > 1 ? (same ? "ok" : "bad") : "",
    textContent: got.length > 1 ? (same ? `✔ ${got.length} implementations, one hash` : "✗ the hashes differ") : "Start more runtimes to compare." }));
  return rows;
}
async function usePolicy() {
  const text = area.value, path = "policies/my-policy.json";
  if (py.pyodide) { py.pyodide.FS.writeFile("/work/" + path, text); write("py", `(wrote /work/${path} from the editor)\n`, "d"); }
  if (linux.ready) await linuxWrite("/work/" + path, text);
  const cmd = `sharness-ai run --policy ${path} -- sh -c 'id; ls /work; touch /work/t && echo wrote /work/t'`;
  if (linux.emulator) { tab("linux"); T.linux.input.value = cmd; T.linux.input.focus(); }
  else { write("py", `Boot Linux to run under it: ${cmd}\n`, "d"); }
}

window.sharnessPlayground = { pyRun: (l) => pyRun(l, true), linuxRun, bootLinux, startPy, hashEverywhere, usePolicy, state: { py, linux }, netwatch: () => linux.netwatch };
status("py", "not started: Pyodide is about 10 MB from cdn.jsdelivr.net", "");
status("linux", "off: the guest is about 25 MB, then about 30 s of boot", "");
loadPolicy();
startPy().then(() => {}, (e) => { status("py", "Pyodide failed to load: " + e.message, "err"); write("py", String(e) + "\n", "r"); });
