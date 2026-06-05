from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db.init_db import db

logs_router = APIRouter()

#logs need to be immuable READ ONLY

#READ
@logs_router.get("/waf/network_logs")
async def get_logs(limit: int = 100, offset: int = 0):
    rows = db.execute("SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()

    logs_list = []
    for row in rows:
        logs_list.append({
            "log_id": row[0],
            "timestamp": row[1].isoformat() if row[1] else None, 
            "client_ip": row[2],
            "http_method": row[3],
            "request_path": row[4],
            "status_code": row[5],
            "user_agent": row[6],
            "response_time_ms": row[7]
        })
    return {"logs": logs_list}

#ROUTE FOR ANALYTICS !
@logs_router.get("/waf/analytics")
async def get_log_stats():
    
    total_reqs = db.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]

    blocked_requests = db.execute("SELECT COUNT(*) FROM activity_logs WHERE status_code = 403").fetchone()[0]

    #avg response time == doar cererile forwardate (blocate au response_time 0.0)
    avg_response_ms = db.execute(
        "SELECT AVG(response_time_ms) FROM activity_logs WHERE response_time_ms > 0"
    ).fetchone()[0]

    #top 3 cele mai active adrese ip 
    top_ips = db.execute(
        "SELECT client_ip, COUNT(*) as topIPs " \
        " FROM activity_logs " \
        " GROUP BY client_ip " \
        " ORDER BY topIPs DESC " \
        " LIMIT 3"
    ).fetchall()

    #attack types == grupare a blocarilor dupa NUMELE regulii
    attack_types = db.execute(
        "SELECT r.name, COUNT(*) as cnt "
        " FROM firewall_actions fa "
        " LEFT JOIN rules r ON fa.rule_id = r.rule_id "
        " WHERE fa.action_taken = 'BLOCK' AND r.name IS NOT NULL "
        " GROUP BY r.name "
        " ORDER BY cnt DESC "
        " LIMIT 6"
    ).fetchall()

    return{
        "total_requests": total_reqs,
        "blocked_requests": blocked_requests,
        "avg_response_ms": avg_response_ms,
        "top_ips": [{"ip": row[0], "topIPs": row[1]} for row in top_ips],
        "attack_types": [{"type": row[0], "count": row[1]} for row in attack_types],
    }


#debug
@logs_router.get("/waf/debug")
async def debug():
    from db.logger import activity_logs_buffer
    from db.init_db import db
    in_buffer = len(activity_logs_buffer)
    in_db = db.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
    return {"buffer_size": in_buffer, "db_rows": in_db}