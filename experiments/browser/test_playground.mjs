// The playground, driven end to end in headless Chromium: Pyodide installs the dev wheel and
// runs the policy commands; the Linux guest boots to a shell and enforces; three hashes agree.
//   node experiments/browser/test_playground.mjs [out-dir]      (PLAYWRIGHT=… as for boot_browser)
//   PLAYGROUND_URL=https://sharness.ai/code/playground/index.html node …   (test a published copy)
// Needs network for Pyodide (cdn.jsdelivr.net). Exit 0 when every check held.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, extname } from "node:path";
const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(process.argv[2] || HERE + "/out");
const WWW = OUT + "/www";
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".wasm": "application/wasm", ".json": "application/json", ".gz": "application/gzip" };
const server = createServer(async (req, res) => {
  const file = WWW + decodeURIComponent(req.url.split("?")[0]);
  try { const body = await readFile(file); res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" }); res.end(body); }
  catch { res.writeHead(404); res.end(); }
});
await new Promise(r => server.listen(0, "127.0.0.1", r));
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } });
const errors = [];
page.on("pageerror", e => errors.push(String(e)));
// slow the policy files down, as a real network does: a command typed before start-up finishes must still work
await page.route("**/policies/*.json", async (route) => { await new Promise(r => setTimeout(r, 1500)); await route.continue(); });
const checks = [];
const check = (name, ok, detail = "") => { checks.push([name, ok]); console.log(`${ok ? "✔" : "✗"} ${name}${detail ? "  " + detail : ""}`); };
const t0 = Date.now(), secs = () => ((Date.now() - t0) / 1000).toFixed(1) + " s";
await page.goto(process.env.PLAYGROUND_URL || `http://127.0.0.1:${server.address().port}/playground.html`);
await page.waitForFunction(() => window.sharnessPlayground?.state.py.pyodide, null, { timeout: 300000 });   // started, not finished: pyRun must wait for the rest
check("Pyodide loaded", true, secs());
const py = (line) => page.evaluate((l) => window.sharnessPlayground.pyRun(l), line);
await py("pip install sharness-ai");
check("pip install sharness-ai (the dev wheel, by micropip)", await page.evaluate(() => window.sharnessPlayground.state.py.installed), secs());
let out = await py("sharness-ai policy hash policies/p0-hello-world.json");
check("Pyodide: policy hash P0", out.includes("sha256:a6244d346ea9d7955c04defba5e67f71ae9867af618fa21d11589c7ef8449032"));
out = await py("sharness-ai policy translate policies/p1-agent-session.json --to claude-code");
check("Pyodide: policy translate to claude-code", out.includes('"sandbox"') && out.includes("not enforced"));
out = await py("sharness-ai probe");
check("Pyodide: probe says there is no kernel", out.includes("no kernel here"));
out = await py("sharness-ai hello");
check("Pyodide: hello refuses, nothing ran", out.includes("refused") && out.includes("Nothing ran"));
await page.screenshot({ path: OUT + "/playground-pyodide.png" });
await page.evaluate(() => window.sharnessPlayground.bootLinux());
check("Linux booted to a shell", true, secs());
const lx = (line) => page.evaluate((l) => window.sharnessPlayground.linuxRun(l), line);
out = await lx("sharness-ai hello");
check("Linux: hello 6/6 held", out.includes("6/6 held"));
out = await lx("sharness-ai run --policy policies/p2-tool-server.json -- sh -c 'echo hi > /work/x.txt'");
check("Linux: P2 refuses a write", out.includes("Permission denied"));
// the network: the guest's packets become this page's fetch(); the interceptor sees and vetoes them
out = await lx("wget -q -O - -T 20 http://sharness.ai/llms.txt | head -1");
check("Linux: wget through the page's fetch backend", out.includes("# sharness.ai"), out.trim().slice(0, 60));
let flows = await page.evaluate(() => window.sharnessPlayground.netwatch().flows.map(f => ({ proto: f.proto, to: f.to, what: f.what, verdict: f.verdict, status: f.status })));
check("interceptor: DNS, TCP and an allowed HTTP GET 200", flows.some(f => f.proto === "DNS" && f.to === "sharness.ai") && flows.some(f => f.proto === "TCP" && f.to.endsWith(":80")) && flows.some(f => f.proto === "HTTP" && f.verdict === "allowed" && f.status === "200"), JSON.stringify(flows.filter(f => f.proto === "HTTP")));
out = await lx("wget -q -O - -T 20 http://example.com/ 2>&1; echo exit $?");
flows = await page.evaluate(() => window.sharnessPlayground.netwatch().flows.map(f => ({ proto: f.proto, to: f.to, verdict: f.verdict })));
check("interceptor: a host off the allowlist is blocked outside the guest (403)", out.includes("403") && flows.some(f => f.proto === "HTTP" && f.to === "example.com" && f.verdict === "blocked"), out.trim().slice(-60));
const count = () => page.evaluate(() => { const fs = window.sharnessPlayground.netwatch().flows; return { tcp: fs.filter(f => f.proto === "TCP" || f.proto === "HTTP").length, dns: fs.filter(f => f.proto === "DNS").length }; });
const before = await count();
out = await lx("sharness-ai run --policy policies/p1-agent-session.json -- wget -q -O - -T 3 http://sharness.ai/llms.txt 2>&1; echo exit $?");
const after = await count();
check("Linux: under P1 (443 only) the kernel refuses port 80: no TCP or HTTP reaches the page", !out.includes("# sharness.ai") && out.includes("Permission denied") && after.tcp === before.tcp, `tcp/http flows ${before.tcp}→${after.tcp}; ${out.trim().slice(-60)}`);
check("interceptor: the DNS query still left (Landlock does not see UDP), as documented", after.dns > before.dns, `dns flows ${before.dns}→${after.dns}`);
out = await lx("sharness-ai run --policy policies/p5-web-fetch.json -- wget -q -O - -T 20 http://sharness.ai/llms.txt | head -1");
check("Linux: under P5 (80 and 443) the fetch succeeds", out.includes("# sharness.ai"));
await page.evaluate(() => { const m = document.querySelector('#pg-netwatch tbody tr:last-child'); if (m) m.click(); });
await page.screenshot({ path: OUT + "/playground-network.png", fullPage: true });
const rows = await page.evaluate(() => window.sharnessPlayground.hashEverywhere());
const hs = rows.map(r => r[1]);
check("one hash in three places (WebCrypto, Pyodide, Linux)", hs.length === 3 && hs.every(h => h === hs[0] && h.startsWith("sha256:")), hs[0]);
await page.screenshot({ path: OUT + "/playground-linux.png" });
check("no page errors", errors.length === 0, JSON.stringify(errors));
console.log(`${checks.filter(c => c[1]).length}/${checks.length} checks held · ${await page.evaluate(() => navigator.userAgent)} · ${secs()}`);
await browser.close(); server.close();
process.exit(checks.every(c => c[1]) ? 0 : 1);
