import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
 
_BASE       = os.path.dirname(os.path.abspath(__file__))
_CONFIG     = os.path.join(_BASE, "waf_config.json")
DEFAULT_PORT = 3001
 
try:
    with open(_CONFIG) as f:
        PORT = json.load(f).get("target_port", DEFAULT_PORT)
except Exception:
    PORT = DEFAULT_PORT
 
 
class AnyHandler(BaseHTTPRequestHandler):
 
    def do_GET(self):    self._ok()
    def do_POST(self):   self._ok()
    def do_PUT(self):    self._ok()
    def do_DELETE(self): self._ok()
    def do_PATCH(self):  self._ok()
    def do_HEAD(self):   self._ok()
    def do_OPTIONS(self):self._ok()
 
    def _ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')
 
    def log_message(self, fmt, *args):
        pass  
 
 
if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), AnyHandler)
    print(f"test app pornita pe :{PORT} — raspunde 200 la orice ruta")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")