from fastapi import APIRouter, HTTPException, Query
from db.init_db import db

waf_actions_router = APIRouter()

@waf_actions_router.get("/waf/actions")
async def get_firewall_actions( limit: int = Query(default=50, ge=1, le=500),
                                offset: int = Query(default=0, ge=0)):
    #fetches every action the fw executed
    #left join to combine action, rule (name + pattern + type) and the request log
    query = """
                    SELECT
                        fa.action_id,
                        fa.timestamp,
                        fa.action_taken,
                        fa.trigger,
                        fa.rule_id,
                        r.name AS rule_name,
                        fa.activity_log_id,
                        al.client_ip,
                        al.request_path,
                        r.match_pattern,
                        r.rule_type
                    FROM firewall_actions fa
                    LEFT JOIN rules r ON fa.rule_id = r.rule_id
                    LEFT JOIN activity_logs al ON fa.activity_log_id = al.log_id
                    ORDER BY fa.timestamp DESC
                    LIMIT ? OFFSET ?
            """

    rows = db.execute(query, (limit, offset)).fetchall()

    total = db.execute("SELECT COUNT (*) FROM firewall_actions").fetchone()[0]

    #data format --> FRONTEND
    waf_actions_list = []
    for row in rows:
        client_ip     = row[7]
        request_path  = row[8]
        match_pattern = row[9]
        rule_type     = row[10]

        # analyzer / scanner blocks are not tied to a single request log
        # -> client_ip is taken from the IP rule pattern, path stays empty
        if not client_ip and rule_type == 'IP_MATCH':
            client_ip = match_pattern

        waf_actions_list.append({
            "action_id": row[0],
            "timestamp": row[1].isoformat() if row[1] else None,
            "action_taken": row[2],
            "trigger": row[3],
            "rule": {
                "id": row[4],
                "name": row[5] or "Blank"
            },
            "network":{
                "log_id": row[6],
                "client_ip": client_ip or "",      # empty, not "Unknown"
                "request_path": request_path or ""  # empty, not "Unknown"
            }
        })

    return {
        "data": waf_actions_list,
        "pagination": {
            "total_recs": total,
            "current_pg": (offset // limit) + 1,
            "total_pg": (total + limit - 1) // limit,
            "limit": limit
        }
    }

#route for getting a single action --> for detailed view in front
@waf_actions_router.get("/waf/actions/{action_id}")
async def get_action_by_id(action_id: str):
    query = (
        "SELECT "
        "fa.action_id, fa.timestamp, fa.action_taken, fa.trigger, "
        "r.name, r.match_pattern, r.rule_type, "
        "al.client_ip, al.http_method, al.request_path, al.user_agent "
        "FROM firewall_actions fa "
        "LEFT JOIN rules r ON fa.rule_id = r.rule_id "
        "LEFT JOIN activity_logs al ON fa.activity_log_id = al.log_id "
        "WHERE fa.action_id = ?"
    )

    row = db.execute(query, (action_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Action ID not found")

    client_ip     = row[7]
    rule_type     = row[6]
    match_pattern = row[5]
    if not client_ip and rule_type == 'IP_MATCH':
        client_ip = match_pattern

    return {
        "action_id": row[0],
        "timestamp": row[1].isoformat() if row[1] else None,
        "action_taken": row[2],
        "trigger": row[3],
        "rule_name": row[4],
        "client_ip": client_ip or "",
        "http_method": row[8] or "",
        "request_path": row[9] or "",
        "user_agent": row[10] or ""
    }