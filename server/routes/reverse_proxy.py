from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

import httpx
import uuid
# decoding for path traversal
import urllib.parse

from datetime import datetime
import time

from db.init_db import CACHE_IPS, CACHE_REGEX
from db.logger import activity_logs_buffer, firewall_actions_buffer
from db.sanitize_data import sanitize_ip, sanitize_path
#proxy state from waf config
from .waf_config import PROXY_STATE

proxy_router = APIRouter()

def _resolve_client_ip(request: Request) -> str:
    #simulation testing only
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()
    return request.client.host

#log only function for log only rules
async def _log_only(rule_id: int, trigger: str, request_id: str, timestamp):
    firewall_actions_buffer.append((str(uuid.uuid4()), timestamp, request_id, rule_id, "LOG WARNING", sanitize_path(trigger)))

# this prevents HTTP VERB TAMPERING
@proxy_router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def reverse_proxy(request: Request, path: str):
    #  metadata 
    start_time = time.time()
    request_id = str(uuid.uuid4())
    timestamp  = datetime.now()

    client_ip  = _resolve_client_ip(request)
    method     = request.method
    user_agent = request.headers.get("user-agent", "Unknown")

    #  URL decoding 
    raw_path_bytes = request.scope.get("raw_path", b"")
    raw_path  = raw_path_bytes.decode("utf-8", errors="ignore")

    raw_query_bytes=request.scope.get("query_string", b"")
    raw_query = raw_query_bytes.decode("utf-8", errors="ignore")

    # Two unquote passes: first pass decodes %2e == .
    #                     second pass decodes %252e == %2e == .  (double-encoded)
    full_path    = urllib.parse.unquote(urllib.parse.unquote(raw_path))
    query_string = urllib.parse.unquote(urllib.parse.unquote(raw_query))

    # helper: block & log 
    async def block_request(rule_id: int, trigger: str, reason: str):
        print(f"[WAF BLOCK] IP={client_ip} | rule={rule_id} | trigger={trigger!r} | reason={reason}")

        activity_logs_buffer.append((request_id, timestamp, sanitize_ip(client_ip), method,
                            sanitize_path(full_path), 403, user_agent, 0.0))
        firewall_actions_buffer.append((str(uuid.uuid4()), timestamp, request_id, rule_id, "BLOCK", sanitize_path(trigger)))

        return JSONResponse({"error": "Access denied!"}, status_code=403)

    # SECURITY CHECKS  (ordered fastest to slowest)

    #  Check 1 = blocked IP 
    if sanitize_ip(client_ip) in CACHE_IPS:
        return await block_request(0, sanitize_ip(client_ip), "Blocked IP by FIREWALL rule")

    #  Check 2 = malicious PATH 
    for rule in CACHE_REGEX['PATH']:
        target = full_path
        match  = rule['pattern'].search(target)
        if match:
            if rule['action'] == 'BLOCK':
                return await block_request(rule['rule_id'], match.group(0), "Malicious path pattern detected")
            await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    #  Check 3 = malicious QUERY STRING 
    for rule in CACHE_REGEX['QUERY_STRING']:
        target =  query_string
        search_target = target
        match = rule['pattern'].search(search_target)
        if match:
            if rule['action'] == 'BLOCK':
                return await block_request(rule['rule_id'], match.group(0), "Malicious query string detected")
            await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    #  Check 4 = malicious HEADERS 
    for header_name, header_value in request.headers.items():
        merged_header = f"{header_name}: {header_value}"
        for rule in CACHE_REGEX['HEADERS']:
            match = rule['pattern'].search(merged_header)
            if match:
                if rule['action'] == 'BLOCK':
                    return await block_request(rule['rule_id'], match.group(0), "Malicious HTTP header detected")
                await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    # Check 5 : malicious BODY 
    body_bytes: bytes = b""

    if method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()

        if body_bytes:
            body_string = body_bytes.decode("utf-8", errors="ignore")

            for rule in CACHE_REGEX['BODY']:
                match = rule['pattern'].search(body_string)
                if match:
                    if rule['action'] == 'BLOCK':
                        return await block_request(rule['rule_id'], match.group(0), "Malicious payload in request body")
                    await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    # FORWARD clean traffic to the protected app
    client = PROXY_STATE.get("client")

    if client is None:
        return JSONResponse(
            {"error":"WAF not configured! Visit the home page first:)"},
            status_code=503
        )
    
    cfg = PROXY_STATE.get("config", {})
    target_URL = f"http://{cfg.get('target_host', '127.0.0.1')}:{cfg.get('target_port', 3000)}"
    
    raw_uri = raw_path

    if raw_query:
        raw_uri += f"?{raw_query}"

    url = f"{target_URL}{raw_uri}"

    headers = dict(request.headers)
    headers.pop("host", None)   # httpx sets the correct Host for the target

    try:

        if method in ("POST", "PUT", "PATCH"):
            target_req = client.build_request(
                method, url, headers=headers,
                content=body_bytes
            )
        else:
            target_req = client.build_request(
                method, url, headers=headers,
                content=request.stream()
            )

        target_resp = await client.send(target_req, stream=True)
        status_code = target_resp.status_code

    except httpx.ConnectError:
        status_code = 502
        return JSONResponse(
            {"error": f"WAF could not reach target at {target_URL}"},
            status_code=502
        )

    response_time_ms = round((time.time() - start_time) * 1000, 2)

    activity_logs_buffer.append((request_id, timestamp, sanitize_ip(client_ip), method,
                       sanitize_path(full_path), status_code, user_agent, response_time_ms))

    return StreamingResponse(
        target_resp.aiter_raw(),
        status_code=status_code,
        headers=dict(target_resp.headers),
        background=target_resp.aclose
    )