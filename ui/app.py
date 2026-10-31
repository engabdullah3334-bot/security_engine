# -*- coding: utf-8 -*-
"""
security_engine/ui/app.py
=========================
Minimalist, calm, zero-dependency standalone Web UI for `SecurityEngine`.
Sole purpose: clearly present `SecurityEngine`'s mission and execute file
inspection without intruding on core engine logic or requiring external UI frameworks.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from security_engine import SecurityEngine, SecurityRejectedError

DEFAULT_SAFE_DIR = str(Path(__file__).resolve().parent.parent / "safe_files")

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Engine</title>
<style>
  :root { --bg:#f8fafc; --card:#ffffff; --border:#e2e8f0; --text:#0f172a; --muted:#64748b; --accent:#334155; --accent-hover:#1e293b; --ok-bg:#ecfdf5; --ok-txt:#065f46; --err-bg:#fef2f2; --err-txt:#991b1b; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; background:var(--bg); color:var(--text); line-height:1.55; }
  .wrap { max-width:780px; margin:2.5rem auto; padding:0 1.25rem; }
  h1 { font-size:1.35rem; font-weight:600; margin:0 0 1rem; letter-spacing:-0.01em; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.25rem 1.4rem; margin-bottom:1.1rem; }
  .label { font-size:0.73rem; font-weight:600; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); margin-bottom:0.35rem; }
  .mission { margin:0 0 0.75rem; color:#334155; font-size:0.94rem; }
  .contracts { font-size:0.83rem; color:var(--muted); padding-top:0.65rem; border-top:1px solid var(--border); }
  .contracts code, pre { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; background:#f1f5f9; padding:0.12rem 0.38rem; border-radius:4px; font-size:0.82rem; }
  .row { display:grid; grid-template-columns:1fr 1fr; gap:0.9rem; margin-bottom:0.9rem; }
  label.field { display:block; font-size:0.83rem; color:var(--muted); margin-bottom:0.3rem; }
  input[type="text"], input[type="number"], select, input[type="file"] { width:100%; padding:0.55rem 0.7rem; border:1px solid var(--border); border-radius:7px; font-size:0.88rem; background:#fff; color:var(--text); }
  .actions { display:flex; gap:0.6rem; align-items:center; margin-top:0.9rem; flex-wrap:wrap; }
  button { padding:0.58rem 1.1rem; border-radius:7px; border:1px solid transparent; font-size:0.88rem; font-weight:500; cursor:pointer; background:var(--accent); color:#fff; transition:background .15s; }
  button:hover { background:var(--accent-hover); }
  button.secondary { background:#fff; color:var(--text); border-color:var(--border); }
  button.secondary:hover { background:#f1f5f9; }
  .banner { padding:0.75rem 1rem; border-radius:8px; font-size:0.88rem; font-weight:500; margin-bottom:0.9rem; }
  .banner.ok { background:var(--ok-bg); color:var(--ok-txt); border:1px solid #a7f3d0; }
  .banner.err { background:var(--err-bg); color:var(--err-txt); border:1px solid #fecaca; }
  pre { padding:0.85rem; overflow-x:auto; margin:0.4rem 0 0; border:1px solid var(--border); border-radius:7px; }
  .hidden { display:none; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Security Engine</h1>
  <div class="card">
    <div class="label">Engine Mission</div>
    <p class="mission">Entry-gate security auditor that inspects raw untrusted files across multi-layer checks (existence, extension policy, size ceiling, magic-byte signature &amp; archive-bomb verification) and computes streaming cryptographic hashes.</p>
    <div class="contracts"><b>Input:</b> Raw uninspected file &nbsp;&middot;&nbsp; <b>Output:</b> Verified <code>safe_path</code> + <code>SHA-256</code> &amp; <code>MD5</code>, or <code>SecurityRejectedError</code></div>
  </div>

  <div class="card">
    <div class="row">
      <div>
        <label class="field">Input Mode</label>
        <select id="modeSelect" onchange="toggleUpload()">
          <option value="upload">Upload Raw File</option>
          <option value="sample_valid">Built-in Sample: Valid PDF</option>
          <option value="sample_spoofed">Built-in Sample: Spoofed Executable (.pdf)</option>
        </select>
      </div>
      <div>
        <label class="field">Max Size Limit (MB)</label>
        <input type="number" id="maxMb" value="100" step="1" min="0.1">
      </div>
    </div>
    <div id="uploadBox" style="margin-bottom:0.9rem;">
      <label class="field">Select Raw File</label>
      <input type="file" id="fileInput">
    </div>
    <div>
      <label class="field">Safe Output Directory</label>
      <input type="text" id="safeDir" value="__DEFAULT_SAFE_DIR__">
    </div>
    <div class="actions">
      <button onclick="runInspect()">Inspect File</button>
      <button class="secondary hidden" id="dlBtn" onclick="downloadJson()">Download JSON</button>
    </div>
  </div>

  <div id="resultCard" class="card hidden">
    <div id="verdictBanner" class="banner"></div>
    <div class="label">Structured Output</div>
    <pre id="jsonOut"></pre>
  </div>
</div>

<script>
let lastOutput = null;
function toggleUpload() {
  const m = document.getElementById('modeSelect').value;
  document.getElementById('uploadBox').style.display = (m === 'upload') ? 'block' : 'none';
}
function toBase64(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result.split(',')[1] || '');
    r.onerror = rej;
    r.readAsDataURL(file);
  });
}
async function runInspect() {
  const mode = document.getElementById('modeSelect').value;
  const payload = {
    mode: mode,
    max_mb: parseFloat(document.getElementById('maxMb').value || '100'),
    safe_dir: document.getElementById('safeDir').value
  };
  if (mode === 'upload') {
    const f = document.getElementById('fileInput').files[0];
    if (!f) { alert('Please choose a file first.'); return; }
    payload.file_name = f.name;
    payload.file_b64 = await toBase64(f);
  }
  const resp = await fetch('/api/inspect', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  lastOutput = data;
  const card = document.getElementById('resultCard');
  const banner = document.getElementById('verdictBanner');
  card.classList.remove('hidden');
  document.getElementById('dlBtn').classList.remove('hidden');
  if (data.ok) {
    banner.className = 'banner ok';
    banner.textContent = 'SAFE — SHA-256: ' + data.result.sha256_hash.slice(0, 24) + '...';
    document.getElementById('jsonOut').textContent = JSON.stringify(data.result, null, 2);
  } else {
    banner.className = 'banner err';
    banner.textContent = 'REJECTED [' + (data.error.code || 'ERROR') + '] — ' + (data.error.reason || data.error);
    document.getElementById('jsonOut').textContent = JSON.stringify(data.error, null, 2);
  }
}
function downloadJson() {
  if (!lastOutput) return;
  const blob = new Blob([JSON.stringify(lastOutput, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'security_result.json';
  a.click();
}
</script>
</body>
</html>
"""


def execute_inspection(payload: dict[str, Any]) -> dict[str, Any]:
    mode = payload.get("mode", "sample_valid")
    max_mb = float(payload.get("max_mb") or 100.0)
    safe_dir = payload.get("safe_dir") or DEFAULT_SAFE_DIR

    engine = SecurityEngine(safe_dir=safe_dir, max_size_mb=max_mb, mode="copy")
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        if mode == "upload":
            fname = payload.get("file_name") or "uploaded.bin"
            raw_bytes = base64.b64decode(payload.get("file_b64") or "")
            candidate = tmp / Path(fname).name
            candidate.write_bytes(raw_bytes)
        elif mode == "sample_spoofed":
            candidate = tmp / "disguised_invoice.pdf"
            candidate.write_bytes(b"MZ\x90\x00PE_EXECUTABLE_DISGUISED_AS_PDF")
        else:
            candidate = tmp / "clean_sample.pdf"
            candidate.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n")

        try:
            res = engine.inspect(candidate)
            return {"ok": True, "result": res.to_dict()}
        except SecurityRejectedError as err:
            return {"ok": False, "error": err.to_dict()}
        except Exception as exc:
            return {"ok": False, "error": {"code": "RUNTIME_ERROR", "reason": str(exc)}}


class SecurityUIHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        html = HTML_PAGE.replace("__DEFAULT_SAFE_DIR__", DEFAULT_SAFE_DIR.replace("\\", "/"))
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/api/inspect":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = json.loads(self.rfile.read(length).decode("utf-8"))
        out = json.dumps(execute_inspection(raw), ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def _pick_port(preferred: int = 8701) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(("127.0.0.1", preferred)) != 0:
            return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def serve_ui(host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> None:
    actual_port = port or _pick_port(8701)
    server = ThreadingHTTPServer((host, actual_port), SecurityUIHandler)
    url = f"http://{host}:{actual_port}"
    print(f"Security Engine UI running at {url} (Press Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Security Engine UI.")
    finally:
        server.server_close()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Security Engine Standalone UI")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--no-browser", action="store_true")
    args = p.parse_args()
    serve_ui(port=args.port, open_browser=not args.no_browser)
