"""The live page: one HTML file served on loopback under a random token, and a server-sent event
stream of the traffic (the net door's audit), the processes of the shell's uid and the decisions
(every refusal, by whom). Plain HTTP on 127.0.0.1 with the token in the path; the page holds no
secret and shows no body, only what the audit lines hold."""
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sharness_ai.launcher.Watch import processes

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>sharness-ai shell</title>
<style>
body{margin:0;font:14px ui-monospace,Menlo,Consolas,monospace;background:#0b1020;color:#e5e7eb}
header{padding:10px 16px;background:#161b2e;display:flex;gap:18px;align-items:baseline}
header b{color:#7dd3fc}.dim{color:#9ca3af}
main{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:12px}
section{background:#111633;border:1px solid #2a3159;border-radius:8px;min-height:160px;overflow:auto;max-height:46vh}
section h2{margin:0;padding:8px 12px;font-size:13px;color:#c4b5fd;border-bottom:1px solid #2a3159;position:sticky;top:0;background:#111633}
table{width:100%;border-collapse:collapse}td,th{padding:3px 10px;text-align:left;white-space:nowrap;font-size:12.5px}th{color:#9ca3af;font-weight:normal}
tr:nth-child(even){background:#0f1430}.ok{color:#4ade80}.no{color:#f87171}.warn{color:#fbbf24}
#decisions{grid-column:1/3}.caveat{padding:8px 16px;color:#9ca3af;font-size:12px}
</style></head><body>
<header><b>sharness-ai shell</b><span id="who" class="dim"></span><span id="counts" class="dim"></span></header>
<main>
<section><h2>traffic: what the shell asked sharness.net.proxy</h2><table id="traffic"><tr><th>at</th><th>method</th><th>host:port</th><th>bytes</th><th>verdict</th></tr></table></section>
<section><h2>processes: the shell's uid</h2><table id="procs"><tr><th>pid</th><th>ppid</th><th>rss</th><th>nnp</th><th>command</th></tr></table></section>
<section id="decisions"><h2>decisions: every refusal, and who made it</h2><table id="dec"><tr><th>at</th><th>by</th><th>what</th><th>reason</th><th>row</th></tr></table></section>
</main>
<p class="caveat">The kernel holds the shell's files, its one port and its caps (Landlock, rlimits); sharness.net.proxy holds the hosts. A policy the launcher applies to the shell is a Boundary for the shell; the launcher itself is a Setting until a launcher above it binds it. Kernel refusals are not yet shown here (Landlock audit, a later step); the shell sees them as EACCES.</p>
<script>
const seen = new Set();
function row(t, cells, cls){const tr=document.createElement('tr');if(cls)tr.className=cls;cells.forEach(c=>{const td=document.createElement('td');td.textContent=c;tr.appendChild(td)});t.appendChild(tr);t.parentElement.scrollTop=t.parentElement.scrollHeight;return tr}
function refresh(d){for (const l of d.traffic){const k=l.at+l.method+l.path+l.status+(l.allowed?'':l.reason);const tr=document.querySelector(`#traffic tr[data-k="${CSS.escape(k)}"]`);if(tr&&tr.cells[3].textContent!=String(l.bytes))tr.cells[3].textContent=l.bytes}}
const es = new EventSource('events');
es.onmessage = e => {
  const d = JSON.parse(e.data);
  document.getElementById('who').textContent = `uid ${d.uid} · proxy 127.0.0.1:${d.proxy_port} · hosts ${d.hosts.join(' ')||'none'} · ${d.workspace}`;
  document.getElementById('counts').textContent = `${d.allowed} allowed · ${d.refused} refused · ${d.processes.length} processes`;
  for (const l of d.traffic) { const k = l.at+l.method+l.path+l.status+(l.allowed?'':l.reason); if (seen.has(k)) continue; seen.add(k);
    const tr = row(document.getElementById('traffic'), [l.at.slice(11,19), l.method, l.path, l.bytes, l.allowed?'allowed':('refused '+(l.reason||''))], l.allowed?'ok':'no'); tr.dataset.k = k;
    if (!l.allowed) row(document.getElementById('dec'), [l.at.slice(11,19), l.door, l.method+' '+l.path, l.reason||'', l.row||''], 'no'); }
  refresh(d);
  const p = document.getElementById('procs'); while (p.rows.length > 1) p.deleteRow(1);
  for (const x of d.processes) row(p, [x.pid, x.ppid, x.rss_kb+' kB', x.no_new_privs, x.cmd]);
};
</script></body></html>"""


class UI:
    def __init__(self, state: dict, audits: list, uid: int = None, host: str = "127.0.0.1", port: int = 0):
        self.state, self.audits, self.uid, self.host, self.port = state, audits, uid, host, port
        self.token = secrets.token_urlsafe(12)
        self.server = None

    def snapshot(self) -> dict:
        lines = [x for a in self.audits for x in a.dump()]
        return {**self.state, "traffic": lines[-200:], "processes": processes(self.uid),
                "allowed": sum(1 for x in lines if x["allowed"]), "refused": sum(1 for x in lines if not x["allowed"] and x["status"])}

    def serve(self) -> str:
        ui = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                if self.path == f"/{ui.token}/":
                    body = PAGE.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == f"/{ui.token}/events":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    try:
                        while not ui.state.get("stopped"):
                            self.wfile.write(f"data: {json.dumps(ui.snapshot())}\n\n".encode())
                            self.wfile.flush()
                            time.sleep(1)
                    except OSError:
                        return
                else:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://{self.host}:{self.port}/{self.token}/"

    def stop(self):
        self.state["stopped"] = True
        if self.server:
            self.server.shutdown()
            self.server.server_close()
