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


#proxy state from waf config
from .waf_config import PROXY_STATE


proxy_router = APIRouter()

# target app URL ==> trb variabila globala env
#PORT 3000 ==> protected app port

# target_URL = "http://localhost:3000"
# client = httpx.AsyncClient(base_url=target_URL)

# Rules that must be evaluated against the RAW (un-decoded) path/query,
# because their entire purpose is to detect encoding tricks.
# All other rules run against the fully-decoded values.
RAW_PATH_RULES  = {1, 32}   # Block Double URL Encoding (PATH)
RAW_QUERY_RULES = {3, 33}   # Block Double URL Encoding (QUERY)

#log only function for log only rules
async def _log_only(rule_id: int, trigger: str, request_id: str, timestamp):
    #await log_action(timestamp, request_id, rule_id, "LOG WARNING", trigger)
    firewall_actions_buffer.append((str(uuid.uuid4()), timestamp, request_id, rule_id, "LOG WARNING", trigger))

# this prevents HTTP VERB TAMPERING
@proxy_router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def reverse_proxy(request: Request, path: str):

    #  metadata 
    start_time = time.time()
    request_id = str(uuid.uuid4())
    timestamp  = datetime.now()

    client_ip  = request.client.host
    method     = request.method
    user_agent = request.headers.get("user-agent", "Unknown")

    #  URL decoding 
    # Keep the originals for:
    #   1. Forwarding to the protected app (always send what the client sent)
    #   2. Double-encoding detection rules (rules 32, 33)
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

        # await log_activity(request_id, timestamp, client_ip, method,
        #                    full_path, 403, user_agent, 0.0)
        # await log_action(timestamp, request_id, rule_id, "BLOCK", trigger)

        activity_logs_buffer.append((request_id, timestamp, client_ip, method,
                            full_path, 403, user_agent, 0.0))
        firewall_actions_buffer.append((str(uuid.uuid4()), timestamp, request_id, rule_id, "BLOCK", trigger))

        return JSONResponse({"error": "Access denied!"}, status_code=403)

    
    # SECURITY CHECKS  (ordered fastest to slowest)

    #  Check 1 = blocked IP 
    if client_ip in CACHE_IPS:
        return await block_request(0, client_ip, "Blocked IP by FIREWALL rule")

    #  Check 2 = malicious PATH 

    # Double-encoding rules (id in RAW_PATH_RULES) scan the raw undecoded path.
    # Every other PATH rule scans the fully-decoded path so encoded traversal
    # sequences (%2e%2e%2f) are normalised before matching.

    for rule in CACHE_REGEX['PATH']:
        target = raw_path if rule['rule_id'] in RAW_PATH_RULES else full_path
        match  = rule['pattern'].search(target)
        if match:
            if rule['action'] == 'BLOCK':
                return await block_request(rule['rule_id'], match.group(0), "Malicious path pattern detected")
            #LOG-only rules  
            await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    #  Check 3 = malicious QUERY STRING 

    # Always run query checks even if the string is empty — some rules detect
    # malformed characters that an empty-looking string can still contain.

    for rule in CACHE_REGEX['QUERY_STRING']:
        is_raw_rule = int(rule.get('rule_id', -1)) in RAW_QUERY_RULES
        
        target = raw_query if is_raw_rule else query_string
        
        if is_raw_rule and raw_query:
            target = f"?{target}"
            
        search_target = target.lower() if is_raw_rule else target
        match = rule['pattern'].search(search_target)
        
        if match:
            if rule['action'] == 'BLOCK':
                return await block_request(rule['rule_id'], match.group(0), "Malicious query string detected")
            
            await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)


    #  Check 4 = malicious HEADERS 

    # Header values are never URL-encoded by browsers, so no unquote needed.
    # We merge name + value into one string so patterns can optionally match
    # on the header name (e.g. "Cookie: ... union select ...").

    for header_name, header_value in request.headers.items():
        merged_header = f"{header_name}: {header_value}"
        for rule in CACHE_REGEX['HEADERS']:
            match = rule['pattern'].search(merged_header)
            if match:
                if rule['action'] == 'BLOCK':
                    return await block_request(rule['rule_id'], match.group(0), "Malicious HTTP header detected")
                await _log_only(rule['rule_id'], match.group(0), request_id, timestamp)

    # Check 5 : malicious BODY 

    # Only POST / PUT / PATCH can carry a body worth inspecting.
    # We read the entire body once, run all BODY rules, then pass the raw bytes
    # directly to the forwarded request — no stream-rebuilding hack needed.

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
     
    # Always forward the ORIGINAL raw URL never the decoded version
    # The protected app expects what the client actually sent

    #live client from proxy state used
    client = PROXY_STATE.get("client")

    if client is None:
        return JSONResponse(
            {"error":"WAF not configured! Visit the home page first:)"},
            status_code=503
        )
    
    cfg = PROXY_STATE.get("config", {})
    target_URL = f"http://{cfg.get('target_host', '127.0.0.1')}:{cfg.get('target_port', 3000)}"
    
    raw_uri = raw_path + (f"?{raw_query}")
    
    if raw_query:
        raw_uri += f"?{raw_query}"
    
    url = f"{target_URL}{raw_uri}"

    headers = dict(request.headers)
    headers.pop("host", None)   # httpx sets the correct Host for the target


    # Build the outgoing request.
    # For methods with a body we pass body_bytes directly (already read above).
    # For methods without a body we stream from the original request object.
    try:

        if method in ("POST", "PUT", "PATCH"):
            target_req = client.build_request(
                method, url, headers=headers,
                content=body_bytes          # bytes, not a stream (simplitate + sigurata)
            )
        else:
            target_req = client.build_request(
                method, url, headers=headers,
                content=request.stream()    # stream passthrough for GET/HEAD/etc.
            )

    #  send & stream back the response 
        target_resp = await client.send(target_req, stream=True)
        status_code = target_resp.status_code

    except httpx.ConnectError:
        status_code = 502
        return JSONResponse(
            {"error": f"WAF could not reach target at {target_URL}"},
            status_code=502
        )

    response_time_ms = round((time.time() - start_time) * 1000, 2)

    # await log_activity(request_id, timestamp, client_ip, method,
    #                    full_path, status_code, user_agent, response_time_ms)
    activity_logs_buffer.append((request_id, timestamp, client_ip, method,
                       full_path, status_code, user_agent, response_time_ms))

    return StreamingResponse(
        target_resp.aiter_raw(),
        status_code=status_code,
        headers=dict(target_resp.headers),
        background=target_resp.aclose
    )