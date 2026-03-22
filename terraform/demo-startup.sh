#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/demo-setup.log) 2>&1
echo "=== Demo App Setup: $(date) ==="

if systemctl is-active --quiet sso-demo; then
    echo "Already running"; exit 0
fi

apt-get update -qq
apt-get install -y -qq python3

# Get SSO system IP from instance metadata
SSO_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/sso-system-ip 2>/dev/null || echo "")

mkdir -p /opt/sso-demo
cat > /opt/sso-demo/app.py << 'PYAPP'
#!/usr/bin/env python3
"""Demo application protected by MILNET SSO"""
import http.server, json, urllib.request, urllib.parse, os, secrets

SSO_PUBLIC_URL = os.environ.get("SSO_PUBLIC_URL", "https://sso-system.dmj.one")
SSO_INTERNAL_URL = os.environ.get("SSO_INTERNAL_URL", "http://127.0.0.1:80")
DEMO_URL = os.environ.get("DEMO_URL", "https://sso-system-demo.dmj.one")
CLIENT_ID = os.environ.get("CLIENT_ID", "demo-app")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "demo-secret")

HTML_LANDING = """<!DOCTYPE html><html><head><title>Demo App - MILNET SSO</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0a0a0a;color:#c0c0c0;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{text-align:center;max-width:600px;padding:40px}h1{color:#00d4ff;font-size:2rem;margin-bottom:10px}h2{color:#00ff41;font-size:1rem;margin-bottom:30px;font-weight:400}.s{background:#111;border:1px solid #222;border-radius:8px;padding:30px;margin:20px 0}.s .l{color:#666;font-size:.8rem;text-transform:uppercase;margin-bottom:5px}.s .v{color:#ff3333;font-size:1.1rem}.p{background:#1a0000;border:1px solid #330000;border-radius:8px;padding:30px;margin:20px 0}.p h3{color:#ff3333;margin-bottom:15px}a.b{display:inline-block;background:#00ff41;color:#000;padding:15px 40px;font-weight:700;font-size:1rem;text-decoration:none;border-radius:4px;margin-top:20px}.badge{display:inline-block;background:#002200;border:1px solid #00ff41;color:#00ff41;padding:4px 12px;border-radius:20px;font-size:.7rem;margin-bottom:20px}.f{margin-top:40px;color:#333;font-size:.7rem}</style></head><body>
<div class="c"><div class="badge">DEMO APPLICATION</div><h1>Secure Portal</h1><h2>Protected by MILNET SSO System</h2>
<div class="s"><div class="l">Authentication Status</div><div class="v">NOT AUTHENTICATED</div></div>
<div class="p"><h3>Access Restricted</h3><p>This application requires authentication via the MILNET SSO system.</p></div>
<a href="/login" class="b">LOGIN WITH MILNET SSO</a>
<div class="f">SSO: sso-system.dmj.one | Demo: sso-system-demo.dmj.one</div></div></body></html>"""

HTML_AUTH = """<!DOCTYPE html><html><head><title>Demo App - Authenticated</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#0a0a0a;color:#c0c0c0;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{text-align:center;max-width:700px;padding:40px}h1{color:#00d4ff;font-size:2rem;margin-bottom:10px}h2{color:#00ff41;font-size:1rem;margin-bottom:30px;font-weight:400}.s{background:#0a1a0a;border:1px solid #003300;border-radius:8px;padding:30px;margin:20px 0}.s .l{color:#666;font-size:.8rem;text-transform:uppercase;margin-bottom:5px}.s .v{color:#00ff41;font-size:1.1rem}.ui{background:#111;border:1px solid #222;border-radius:8px;padding:20px;margin:10px 0;text-align:left}.fi{margin:10px 0;display:flex;justify-content:space-between;border-bottom:1px solid #1a1a1a;padding-bottom:8px}.fi .k{color:#00ff41}.fi .val{color:#fff}.tb{background:#0a0a0a;border:1px solid #333;padding:15px;border-radius:4px;word-break:break-all;font-size:.75rem;color:#ffaa00;margin:15px 0;text-align:left;max-height:100px;overflow-y:auto}a.lo{display:inline-block;background:#ff3333;color:#fff;padding:12px 30px;font-weight:700;text-decoration:none;border-radius:4px;margin-top:20px}.badge{display:inline-block;background:#002200;border:1px solid #00ff41;color:#00ff41;padding:4px 12px;border-radius:20px;font-size:.7rem;margin-bottom:20px}.sb{display:inline-block;background:#001a33;border:1px solid #00d4ff;color:#00d4ff;padding:4px 12px;border-radius:20px;font-size:.7rem;margin-bottom:20px;margin-left:10px}.f{margin-top:40px;color:#333;font-size:.7rem}</style></head><body>
<div class="c"><div class="badge">DEMO APPLICATION</div><div class="sb">SSO AUTHENTICATED</div><h1>Secure Portal</h1><h2>Authentication Successful via MILNET SSO</h2>
<div class="s"><div class="l">Authentication Status</div><div class="v">AUTHENTICATED</div></div>
<div class="ui"><h3 style="color:#00d4ff;margin-bottom:15px">User Information (from SSO)</h3>{fields}</div>
<div class="tb"><strong style="color:#666">ID Token:</strong><br>{token}</div>
<a href="/logout" class="lo">LOGOUT</a>
<div class="f">Authenticated via sso-system.dmj.one</div></div></body></html>"""

sessions = {}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            sid = None
            for p in self.headers.get("Cookie","").split(";"):
                p = p.strip()
                if p.startswith("session="): sid = p.split("=",1)[1]
            if sid and sid in sessions:
                c = sessions[sid]
                f = "".join(f'<div class="fi"><span class="k">{k}</span><span class="val">{v}</span></div>' for k,v in c["claims"].items())
                html = HTML_AUTH.replace("{fields}",f).replace("{token}",c.get("id_token",""))
                self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                self.wfile.write(html.encode())
            else:
                self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                self.wfile.write(HTML_LANDING.encode())
        elif self.path == "/login":
            s = secrets.token_hex(16)
            p = urllib.parse.urlencode({"client_id":CLIENT_ID,"redirect_uri":f"{DEMO_URL}/callback","response_type":"code","scope":"openid profile","state":s})
            self.send_response(302); self.send_header("Location",f"{SSO_PUBLIC_URL}/oauth/authorize?{p}"); self.end_headers()
        elif self.path.startswith("/callback"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            code = q.get("code",[None])[0]
            if code:
                try:
                    d = urllib.parse.urlencode({"grant_type":"authorization_code","code":code,"redirect_uri":f"{DEMO_URL}/callback","client_id":CLIENT_ID,"client_secret":CLIENT_SECRET}).encode()
                    r = urllib.request.Request(f"{SSO_INTERNAL_URL}/oauth/token",data=d,method="POST")
                    r.add_header("Content-Type","application/x-www-form-urlencoded")
                    with urllib.request.urlopen(r,timeout=10) as resp: tr = json.loads(resp.read())
                    import base64
                    it = tr.get("id_token",""); parts = it.split(".")
                    cl = json.loads(base64.urlsafe_b64decode(parts[1]+"="*(4-len(parts[1])%4))) if len(parts)>=2 else {"sub":"?"}
                    sid = secrets.token_hex(32)
                    sessions[sid] = {"claims":cl,"id_token":it,"access_token":tr.get("access_token","")}
                    self.send_response(302); self.send_header("Set-Cookie",f"session={sid}; Path=/; HttpOnly"); self.send_header("Location","/"); self.end_headers(); return
                except Exception as e:
                    self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers()
                    self.wfile.write(f'<html><body style="background:#0a0a0a;color:#ff3333;font-family:monospace;padding:40px"><h1>SSO Error</h1><p>{e}</p><a href="/" style="color:#00ff41">Back</a></body></html>'.encode()); return
            self.send_response(400); self.end_headers()
        elif self.path == "/logout":
            for p in self.headers.get("Cookie","").split(";"):
                if p.strip().startswith("session="): sessions.pop(p.strip().split("=",1)[1],None)
            self.send_response(302); self.send_header("Set-Cookie","session=; Path=/; Max-Age=0"); self.send_header("Location","/"); self.end_headers()
        else: self.send_response(404); self.end_headers()
    def log_message(self,*a): pass

if __name__ == "__main__":
    print(f"Demo app | SSO public: {SSO_PUBLIC_URL} | SSO internal: {SSO_INTERNAL_URL}")
    http.server.HTTPServer(("0.0.0.0",80),H).serve_forever()
PYAPP

chmod +x /opt/sso-demo/app.py

# Systemd service
cat > /etc/systemd/system/sso-demo.service << SVC
[Unit]
Description=SSO Demo Application
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sso-demo/app.py
WorkingDirectory=/opt/sso-demo
Environment=SSO_PUBLIC_URL=https://sso-system.dmj.one
Environment=SSO_INTERNAL_URL=http://${SSO_IP:-127.0.0.1}:80
Environment=DEMO_URL=https://sso-system-demo.dmj.one
Environment=CLIENT_ID=demo-app
Environment=CLIENT_SECRET=demo-secret
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable sso-demo
systemctl start sso-demo
sleep 2
curl -s http://localhost:80/ | head -3 && echo " — Demo app ready!"
