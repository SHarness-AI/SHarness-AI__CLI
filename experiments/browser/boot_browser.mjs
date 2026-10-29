// E09 in a browser: serve out/www over HTTP, open it in headless Chromium with Playwright,
// print the guest's serial console, exit 0 when hello held and the guest finished.
//   node experiments/browser/boot_browser.mjs [out-dir]
// Playwright is not a dependency of this repository: point PLAYWRIGHT at an installed copy
// (default: the bare module name), e.g. PLAYWRIGHT=/opt/node22/lib/node_modules/playwright/index.mjs
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, extname, normalize } from "node:path";
const HERE = dirname(fileURLToPath(import.meta.url));
const WWW = resolve(process.argv[2] || HERE + "/out") + "/www";
const { chromium } = await import(process.env.PLAYWRIGHT || "playwright");
const TYPES = { ".html": "text/html", ".mjs": "text/javascript", ".wasm": "application/wasm", ".bin": "application/octet-stream", ".gz": "application/gzip" };
const server = createServer(async (req, res) => {           // plain static files: no COOP/COEP headers on purpose, to show none are needed
  const file = normalize(WWW + decodeURIComponent(req.url.split("?")[0].replace(/\/$/, "/index.html")));
  if (!file.startsWith(WWW + "/")) { res.writeHead(404); res.end(); return; }   // nothing above out/www, whatever the URL says
  try { const body = await readFile(file); res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" }); res.end(body); }
  catch { res.writeHead(404); res.end(); }
});
await new Promise(r => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/index.html`;
const browser = await chromium.launch();
const page = await browser.newPage();
const errors = [];
page.on("pageerror", e => errors.push(String(e)));
page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
const t0 = Date.now();
await page.goto(url);
await page.waitForFunction(() => window.__done === true, null, { timeout: 25 * 60 * 1000, polling: 1000 });
const log = await page.evaluate(() => window.__log);
process.stdout.write(log);
const facts = await page.evaluate(() => ({ ...window.__facts, ua: navigator.userAgent }));
const helloExit = Number((log.match(/SHARNESS-HELLO-EXIT (\d+)/) || [])[1]);
console.log(`${facts.ua} · crossOriginIsolated ${facts.crossOriginIsolated} · SharedArrayBuffer ${facts.sharedArrayBuffer} · wall clock ${((Date.now() - t0) / 1000).toFixed(1)}s · hello exit ${helloExit} · page errors ${JSON.stringify(errors)}`);
await page.screenshot({ path: resolve(process.argv[2] || HERE + "/out") + "/browser.png", fullPage: true });
await browser.close(); server.close();
process.exit(helloExit === 0 && errors.length === 0 ? 0 : 1);
