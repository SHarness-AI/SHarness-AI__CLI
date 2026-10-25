// netwatch: every packet the guest sends or receives passes through this page, so the page can
// see it, decode it, and refuse it. Two taps and one veto:
//   frames   bus "net0-send" (guest → world) and "net0-receive" (world → guest): Ethernet, ARP,
//            IPv4, ICMP, UDP (DHCP, DNS), TCP (flags, HTTP request and status lines)
//   fetch    v86's fetch backend turns a guest HTTP request into fetch(); its `fetch` property
//            is wrapped, so the request is logged with its verdict and blocked when the host is
//            not on the page's egress allowlist. The guest sees a 403 that names the policy.
// The allowlist is enforced outside the guest, by code the guest cannot reach: a Boundary for
// everything inside, root included. Hostnames only; v0 policies say ports, hosts are
// sharness.net's job, and this panel is that job done by the page.
//
//   attachNetwatch(emulator, { mount: HTMLElement, allow: ["sharness.ai"] }) → api
//   api.flows (array), api.allow (array, editable), api.allowAll (bool), api.onchange(fn)

const dec = new TextDecoder();
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const ip4 = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
const mac = (b, o) => [...b.subarray(o, o + 6)].map(x => x.toString(16).padStart(2, "0")).join(":");

function dnsName(b, o) {                       // one DNS name, with pointers followed
  const parts = []; let jumped = false, guard = 0;
  while (o < b.length && guard++ < 64) {
    const len = b[o];
    if (len === 0) { o++; break; }
    if ((len & 0xc0) === 0xc0) { o = ((len & 0x3f) << 8) | b[o + 1]; jumped = true; continue; }
    parts.push(dec.decode(b.subarray(o + 1, o + 1 + len))); o += 1 + len;
  }
  return parts.join(".");
}
function parseDns(p) {
  if (p.length < 12) return null;
  const id = u16(p, 0), flags = u16(p, 2), qd = u16(p, 4), an = u16(p, 6);
  let o = 12; const qs = [];
  const types = { 1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 12: "PTR" };
  for (let i = 0; i < qd && o < p.length; i++) { const n = dnsName(p, o); while (o < p.length && p[o] !== 0) { if ((p[o] & 0xc0) === 0xc0) { o++; break; } o += p[o] + 1; } o += 1; const qt = u16(p, o); o += 4; qs.push(n); qs.type = types[qt] || `type ${qt}`; }
  const answers = [];
  for (let i = 0; i < an && o + 12 <= p.length; i++) {
    while (o < p.length && p[o] !== 0) { if ((p[o] & 0xc0) === 0xc0) { o++; break; } o += p[o] + 1; } o++;
    const type = u16(p, o), rdlen = u16(p, o + 8); o += 10;
    if (type === 1 && rdlen === 4) answers.push(ip4(p, o)); o += rdlen;
  }
  return { id, response: !!(flags & 0x8000), names: qs, answers };
}

export function decodeFrame(f) {
  const b = f instanceof Uint8Array ? f : new Uint8Array(f);
  if (b.length < 14) return { kind: "runt" };
  const type = u16(b, 12);
  if (type === 0x0806) return { kind: "arp", op: u16(b, 20) === 1 ? "who-has" : "is-at", sender: ip4(b, 28), target: ip4(b, 38) };
  if (type !== 0x0800) return { kind: "eth", type: type.toString(16) };
  const ihl = (b[14] & 0x0f) * 4, proto = b[23], src = ip4(b, 26), dst = ip4(b, 30), l4 = 14 + ihl, total = u16(b, 16);
  const end = Math.min(b.length, 14 + total);
  if (proto === 1) return { kind: "icmp", src, dst, type: b[l4] === 8 ? "echo request" : b[l4] === 0 ? "echo reply" : `type ${b[l4]}` };
  if (proto === 17) {
    const sport = u16(b, l4), dport = u16(b, l4 + 2), data = b.subarray(l4 + 8, end);
    if (sport === 68 || dport === 67 || sport === 67) return { kind: "dhcp", src, dst, sport, dport, note: data[0] === 1 ? "request" : "reply" };
    if (dport === 53 || sport === 53) return { kind: "dns", src, dst, sport, dport, dns: parseDns(data) };
    return { kind: "udp", src, dst, sport, dport, bytes: data.length };
  }
  if (proto === 6) {
    const sport = u16(b, l4), dport = u16(b, l4 + 2), doff = (b[l4 + 12] >> 4) * 4, fl = b[l4 + 13];
    const flags = [fl & 2 && "SYN", fl & 16 && "ACK", fl & 8 && "PSH", fl & 1 && "FIN", fl & 4 && "RST"].filter(Boolean).join(",");
    const data = b.subarray(l4 + doff, end);
    let line = "";
    if (data.length > 4) { const head = dec.decode(data.subarray(0, Math.min(data.length, 200))); const m = head.match(/^(?:(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) [^\r\n]*|HTTP\/1\.[01] \d{3}[^\r\n]*)/); if (m) line = m[0]; }
    return { kind: "tcp", src, dst, sport, dport, flags, bytes: data.length, line };
  }
  return { kind: "ip", proto, src, dst };
}

export function attachNetwatch(emulator, opts = {}) {
  const api = { flows: [], allow: [...(opts.allow || [])], allowAll: !!opts.allowAll, listeners: [], onchange(fn) { this.listeners.push(fn); } };
  const changed = () => { for (const fn of api.listeners) fn(api); if (ui) ui.render(); };
  const t0 = performance.now();
  const stamp = () => ((performance.now() - t0) / 1000).toFixed(1) + "s";
  const flowsByKey = new Map();
  const flow = (key, init) => { let f = flowsByKey.get(key); if (!f) { f = { t: stamp(), key, ...init, events: [], bytesOut: 0, bytesIn: 0 }; flowsByKey.set(key, f); api.flows.push(f); } return f; };
  const allowed = (host) => api.allowAll || api.allow.some(a => host === a || host.endsWith("." + a));

  function onFrame(dir, raw) {
    const d = decodeFrame(raw);
    if (d.kind === "arp" || d.kind === "eth" || d.kind === "runt") return;
    if (d.kind === "dhcp") { const f = flow("dhcp", { proto: "DHCP", to: "192.168.86.1 (the page)", what: "address for the guest" }); f.events.push(`${stamp()} ${dir} ${d.note}`); f.result = d.note === "reply" ? "192.168.86.100 offered" : f.result; changed(); return; }
    if (d.kind === "dns") {
      const q = d.dns; if (!q) return;
      const name = q.names[0] || "?";
      const f = flow(`dns:${q.id}:${name}`, { proto: "DNS", to: `${name}`, what: `${q.names.type || "?"} ${name}` });
      if (dir === "out") f.events.push(`${stamp()} query ${name}`);
      else { f.events.push(`${stamp()} answer ${q.answers.join(", ") || "none"}`); f.result = q.answers.length ? `${q.answers[0]} (a fake address the page maps back to the name)` : "no answer"; }
      changed(); return;
    }
    if (d.kind === "icmp") { const f = flow(`icmp:${d.dst}:${d.src}`, { proto: "ICMP", to: dir === "out" ? d.dst : d.src, what: "ping" }); f.events.push(`${stamp()} ${dir} ${d.type}`); if (dir === "in") f.result = "reply from the page"; changed(); return; }
    if (d.kind === "tcp") {
      const peer = dir === "out" ? `${d.dst}:${d.dport}` : `${d.src}:${d.sport}`, local = dir === "out" ? d.sport : d.dport;
      const f = flow(`tcp:${local}:${peer}`, { proto: "TCP", to: peer, what: `connect :${dir === "out" ? d.dport : d.sport}` });
      if (dir === "out") f.bytesOut += d.bytes; else f.bytesIn += d.bytes;
      if (d.flags.includes("SYN") && dir === "out") f.events.push(`${stamp()} SYN → ${peer}`);
      if (d.flags.includes("SYN") && d.flags.includes("ACK") && dir === "in") { f.events.push(`${stamp()} SYN,ACK: the page accepted the connection`); f.result = f.result || "accepted by the page"; }
      if (d.flags.includes("RST") && dir === "in") { f.events.push(`${stamp()} RST: the page refused it`); f.result = "refused by the page: only port 80 is served (HTTP → fetch); no TLS passthrough"; f.verdict = f.verdict || "refused"; }
      if (d.flags.includes("FIN")) f.events.push(`${stamp()} FIN ${dir}`);
      if (d.line) { f.events.push(`${stamp()} ${dir === "out" ? "→" : "←"} ${d.line}`); if (dir === "out") f.what = d.line.split(" ").slice(0, 2).join(" "); else f.status = d.line.split(" ")[1]; }
      changed();
    }
  }
  emulator.add_listener("net0-send", (frame) => onFrame("out", frame));
  emulator.add_listener("net0-receive", (frame) => onFrame("in", frame));

  // the veto: the fetch backend's own fetch, wrapped
  const hook = () => {
    const ad = emulator.network_adapter;
    if (!ad || ad.__netwatch) return;
    const inner = ad.fetch;
    ad.__netwatch = true;
    ad.fetch = async (url, init) => {
      const u = new URL(url), host = u.hostname, method = (init && init.method) || "GET";
      // The guest speaks plain HTTP to the page; the page speaks TLS to the world, where the name
      // can be seen and verified. (A plain-http redirect to https also fails the browser's CORS
      // check, so the upgrade is what makes the request possible at all.)
      if (u.protocol === "http:" && !/\.external$/.test(host)) u.protocol = "https:";
      url = u.href;
      const f = flow(`http:${api.flows.length}:${u.href}`, { proto: "HTTP", to: host, what: `${method} ${u.href}` });
      f.headers = init && init.headers ? [...init.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n") : "";
      if (!allowed(host)) {
        f.verdict = "blocked"; f.result = `403 from the page: ${host} is not on the egress allowlist`;
        f.events.push(`${stamp()} blocked outside the guest: ${host} not in [${api.allow.join(", ")}]`);
        changed();
        return new Response(`blocked by the page's egress policy: ${host} is not on the allowlist [${api.allow.join(", ")}]\n`, { status: 403, statusText: "Forbidden", headers: { "content-type": "text/plain", "x-sharness-egress": "blocked" } });
      }
      f.verdict = "allowed"; f.events.push(`${stamp()} allowed: ${host} on the allowlist; fetch() by the browser`); changed();
      try {
        const r = await inner(url, init);
        f.status = String(r.status); f.result = `${r.status} ${r.statusText || ""} · ${r.headers.get("content-type") || ""}`.trim();
        f.respHeaders = [...r.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n");
        f.events.push(`${stamp()} ← ${r.status} ${r.statusText || ""} (${r.headers.get("content-length") || "?"} bytes, ${r.headers.get("content-type") || ""})`);
        changed(); return r;
      } catch (e) {
        f.verdict = "allowed"; f.result = `fetch failed: ${e.message} (the host sends no CORS header, or this browser has no route); the guest sees 502`; f.events.push(`${stamp()} fetch failed: ${e.message}`); changed(); throw e;
      }
    };
  };
  hook(); emulator.add_listener("emulator-started", hook);

  // the panel
  let ui = null;
  if (opts.mount) {
    const m = opts.mount; m.classList.add("nw");
    m.innerHTML = `
      <div class="nw-bar"><b>Network, seen from outside the guest</b><span class="nw-n"></span>
        <label>egress allowlist <input class="nw-allow" type="text" spellcheck="false" aria-label="allowed hostnames, comma separated"></label>
        <label><input class="nw-all" type="checkbox"> allow every host</label>
        <button type="button" class="nw-clear">clear</button></div>
      <div class="nw-table"><table><thead><tr><th>time</th><th>proto</th><th>to</th><th>what</th><th>verdict</th><th>result</th><th>bytes</th></tr></thead><tbody></tbody></table></div>
      <pre class="nw-detail" hidden></pre>
      <p class="nw-note">Every frame the guest sends is decoded here (ARP, DHCP, DNS, ICMP, TCP, HTTP). The page serves port 80 by turning each HTTP request into the browser's own <code>fetch()</code> over TLS (the page is the TLS client, where the name is seen), and refuses other ports; hosts not on the allowlist get a 403 before any <code>fetch()</code> happens; hosts that send no CORS header fail in the browser and the guest sees a 502. A TCP connect the kernel refuses under a policy never appears here: it never left the process. A DNS query does appear even then, because Landlock does not see UDP: that gap, on screen.</p>`;
    const tbody = m.querySelector("tbody"), detail = m.querySelector(".nw-detail"), allowIn = m.querySelector(".nw-allow"), allIn = m.querySelector(".nw-all"), n = m.querySelector(".nw-n");
    allowIn.value = api.allow.join(", "); allIn.checked = api.allowAll;
    allowIn.onchange = () => { api.allow = allowIn.value.split(",").map(s => s.trim()).filter(Boolean); changed(); };
    allIn.onchange = () => { api.allowAll = allIn.checked; changed(); };
    m.querySelector(".nw-clear").onclick = () => { api.flows.length = 0; flowsByKey.clear(); detail.hidden = true; changed(); };
    tbody.onclick = (e) => { const tr = e.target.closest("tr"); if (!tr) return; const f = api.flows[Number(tr.dataset.i)]; detail.hidden = false;
      detail.textContent = `${f.proto} ${f.what}\nto: ${f.to}\n${f.events.join("\n")}` + (f.headers ? `\n\nrequest headers\n${f.headers}` : "") + (f.respHeaders ? `\n\nresponse headers\n${f.respHeaders}` : ""); };
    ui = { render() {
      n.textContent = `${api.flows.length} flow${api.flows.length === 1 ? "" : "s"}`;
      tbody.innerHTML = api.flows.map((f, i) => `<tr data-i="${i}" class="${f.verdict || ""}"><td>${f.t}</td><td>${f.proto}</td><td>${esc(f.to)}</td><td>${esc(f.what)}</td><td>${f.verdict ? `<span class="v ${f.verdict}">${f.verdict}</span>` : ""}</td><td>${esc(f.result || "")}</td><td>${f.bytesOut || f.bytesIn ? `${f.bytesOut}↑ ${f.bytesIn}↓` : ""}</td></tr>`).join("");
      m.querySelector(".nw-table").scrollTop = 1e9;
    } };
    ui.render();
  }
  return api;
}
const esc = (s) => String(s).replace(/[<>&]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;" }[c]));
