import os
import time
import pandas as pd
import urllib.parse
import http.client
 

PROXY_HOST  = "127.0.0.1"
PROXY_PORT  = 8080          # portul proxy WAF 
DELAY       = 0.05          # 50ms intre cereri (20 req/sec)

CSV_PATH    = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "log_analyzer",
    #trb modificat 
    "activity_logs_synthetic_final_final.csv"
)
 

METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}
 

df   = pd.read_csv(CSV_PATH)
rows = df.sample(frac=0.10, random_state=42).reset_index(drop=True)
total = len(rows)
 
print(f"Fireball WAF — HTTP traffic simulator")
print(f"Target : http://{PROXY_HOST}:{PROXY_PORT}")
print(f"Rows   : {total} (test set)")
print(f"Delay  : {DELAY}s per request  ({1/DELAY:.0f} req/sec)")
print(f"{'─'*52}")
 
ok = blocked = errors = 0
 
for i, row in rows.iterrows():
    method     = str(row["field_a"]).upper()
    raw_path   = str(row["field_b"])
    user_agent = str(row["field_d"])
 
    
    if "?" in raw_path:
        path, qs = raw_path.split("?", 1)
        url = f"{path}?{qs}"
    else:
        url = raw_path
 
    headers = {
        "User-Agent":   user_agent,
        "X-Real-IP":    str(row["client_ip"]),
        "Accept":       "*/*",
        "Connection":   "close",
    }
 
    
    body = None
    if method in METHODS_WITH_BODY:
        body = b""
        headers["Content-Length"] = "0"
 
    try:
        conn = http.client.HTTPConnection(
            PROXY_HOST, PROXY_PORT, timeout=5
        )
        conn.request(method, url, body=body, headers=headers)
        resp = conn.getresponse()
        resp.read()  
        conn.close()
 
        status = resp.status
        if status == 403:
            blocked += 1
            marker = "[BLOCK]"
        elif status >= 500:
            errors += 1
            marker = "[5xx]  "
        else:
            ok += 1
            marker = "[OK]   "
 
        idx = i + 1
        print(f"  {marker} {idx:4d}/{total}  {method:6s}  {status}  {raw_path[:55]}")
 
    except Exception as e:
        errors += 1
        print(f"  [ERR]   {i+1:4d}/{total}  {method:6s}  ERR  {raw_path[:40]} — {e}")
 
    time.sleep(DELAY)
 
print(f"{'─'*52}")
print(f"Complet:  OK={ok}  BLOCK={blocked}  ERR={errors}  TOTAL={total}")
 