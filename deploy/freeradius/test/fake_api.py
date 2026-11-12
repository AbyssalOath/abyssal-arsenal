# Stand-in for Panopticon's /internal/radius API (same contract and reply JSON
# as crates/web/src/panopticon_freeradius.rs), for testing the FreeRADIUS config.
import base64, json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
TOKEN = "0123456789abcdef0123456789abcdef"
GOOD = "Basic " + base64.b64encode(f"freeradius:{TOKEN}".encode()).decode()
def norm(m):
    h = "".join(c for c in (m or "").lower() if c in "0123456789abcdef")
    return ":".join(h[i:i+2] for i in range(0, 12, 2)) if len(h) == 12 else None
def first(attrs, name):
    for k, v in attrs.items():
        if k.lower() == name.lower():
            v = v.get("value", v) if isinstance(v, dict) else v
            return v[0] if isinstance(v, list) else v
# Every value literal ("do_xlat": false), as Panopticon sends them.
L = lambda v: {"value": v, "do_xlat": False}
VLAN = lambda v: {"reply:Tunnel-Type": L("VLAN"), "reply:Tunnel-Medium-Type": L("IEEE-802"), "reply:Tunnel-Private-Group-Id": L(str(v))}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def check(self):
        if self.client_address[0] not in ("127.0.0.1", "::1") or self.headers.get("Authorization") != GOOD:
            print("API: 401 for", self.path, self.headers.get("Authorization"), flush=True); self.reply(401); return False
        return True
    def do_GET(self):
        if not self.check(): return
        u = urlparse(self.path)
        print("API GET", u.path, parse_qs(u.query), flush=True)
        if u.path == "/internal/radius/client":
            ip = parse_qs(u.query)["ip"][0]
            # The name carries an expansion: it must arrive literally.
            return self.reply(200, {"control:FreeRADIUS-Client-IP-Address": L(ip), "control:FreeRADIUS-Client-Secret": L("testing123"), "control:FreeRADIUS-Client-Shortname": L("nas-%{User-Name}")})
        self.reply(404)
    def do_POST(self):
        if not self.check(): return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        attrs = json.loads(body)
        u = urlparse(self.path)
        print("API POST", self.path, json.dumps(attrs, sort_keys=True), flush=True)
        if u.path == "/internal/radius/mab":
            if norm(first(attrs, "User-Name")) is None:
                return self.reply(200, {"control:Auth-Type": L("Reject"), "reply:Reply-Message": L("only 802.1X (EAP) and MAC authentication are accepted")})
            mac = norm(first(attrs, "Calling-Station-Id"))
            if mac == "aa:bb:cc:dd:ee:ff":
                return self.reply(200, {"control:Auth-Type": L("Accept"), **VLAN(10)})
            return self.reply(200, {"control:Auth-Type": L("Reject")})
        if u.path == "/internal/radius/post-auth":
            if norm(first(attrs, "Calling-Station-Id")) == "66:66:66:66:66:66":
                return self.reply(200, {"control:Tmp-String-0": L("reject")})
            return self.reply(200, VLAN(20))
        if u.path == "/internal/radius/accounting":
            return self.reply(204)
        self.reply(404)
HTTPServer(("127.0.0.1", 8080), H).serve_forever()
