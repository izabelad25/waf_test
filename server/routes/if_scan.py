from fastapi import APIRouter
from fastapi.responses import JSONResponse
from db.init_db import db, CACHE_IPS
from db.logger import firewall_actions_buffer
from db.init_db import add_new_rule
from datetime import datetime
import uuid

from db.sanitize_data import sanitize_ip, sanitize_path
 
if_scan_router = APIRouter()
 
 
@if_scan_router.post("/waf/if_scan")
async def run_if_scan():
    
    try:
        from log_analyzer.if_scanner import run_scan
        result = run_scan(db)
        return JSONResponse(result)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        print(f"[IF SCAN ERROR]\n{tb}")
        return JSONResponse({"error": str(e), "traceback": tb}, status_code=500)
 
 
@if_scan_router.post("/waf/if_scan/block/{client_ip:path}")
async def block_ip_from_scan(client_ip: str):
   
    try:
        if client_ip in CACHE_IPS:
            return JSONResponse({"status": "already_blocked", "ip": client_ip})
 
        CACHE_IPS.add(client_ip)
        current_time = datetime.now()
        trigger      = "if_anomaly_scan"
        reason       = f"Blocked by IF anomaly scanner"
 
        new_rule_id = add_new_rule(
            f"Scanner block {client_ip}",
            "IP_MATCH", "IP", client_ip, action="BLOCK"
        )
 
        firewall_actions_buffer.append((
            str(uuid.uuid4()), current_time, sanitize_path(trigger),
            new_rule_id, "BLOCK", sanitize_path(reason)
        ))
 
        return JSONResponse({
            "status":  "blocked",
            "ip":      sanitize_ip(client_ip),
            "rule_id": new_rule_id,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)