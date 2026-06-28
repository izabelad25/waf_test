#server
import asyncio
import sys
import uvicorn

#env
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()

#services
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware 
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

#background services
from db.logger import log_background_listener
from log_analyzer.analyze import analyzer
from db.archiver_db import archiver

#routes
from routes.waf_rules import rule_router
from routes.network_logs import logs_router
from routes.waf_actions_log import waf_actions_router
from routes.reverse_proxy import proxy_router
from routes.waf_config import config_router, init_proxy_state, load_config, PROXY_STATE
from routes.if_scan import if_scan_router

#port binding + setup
from port_config import is_backend_running, print_instructions

#  MIDDLEWARE - security policies (CSP + security headers)
class DashboardCSP(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' http://127.0.0.1:8000; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response


class ProxyCSP(BaseHTTPMiddleware):
  
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        if response.status_code == 403:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; "
                "frame-ancestors 'none';"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
        return response


#  LIFESPAN HANDLERS
@asynccontextmanager
async def dashboard_lifespan(app: FastAPI):
    #=== startup ===
    init_proxy_state()
    
    bg_tasks = [
        asyncio.create_task(log_background_listener(), name="logger"),
        asyncio.create_task(analyzer(), name="analyzer"),
        asyncio.create_task(archiver(), name="archiver"),
    ]
    
    print(r"""       +.+"+.+"+.+"+.+"+.+"+.+""")
    print(r"""+.+"+.+"+.+"WAF ACTIVE "+.+"+.+"+.+""")
    print(r"""       +.+"+.+"+.+"+.+"+.+"+.+""")
    
    try:
        yield  # aplicatia ruleaza intre startup si shutdown
    finally:
        #=== shutdown ===
        print("F i r e b a l l #### shutdown")
        
        #cancel bg tasks
        for task in bg_tasks:
            task.cancel()
        
        await asyncio.gather(*bg_tasks, return_exceptions=True)


@asynccontextmanager
async def proxy_lifespan(app: FastAPI):
    try:
        yield
    finally:
        client = PROXY_STATE.get("client")
        if client is not None:
            try:
                await client.aclose()
                print("[OK] Proxy HTTP client closed")
            except Exception as e:
                print(f"[WARN] Failed to close proxy HTTP client: {e}")


#DASHBOARD APP -- PORT 8000
dashboard_app = FastAPI(title="WAF Dashboard", lifespan=dashboard_lifespan)

dashboard_app.add_middleware(DashboardCSP)
dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"]
)

dashboard_app.include_router(rule_router)
dashboard_app.include_router(logs_router)
dashboard_app.include_router(waf_actions_router)
dashboard_app.include_router(config_router)
dashboard_app.include_router(if_scan_router)

dashboard_app.mount("/client", StaticFiles(directory="client"), name="client")

@dashboard_app.get("/")
async def load_dashboard():
    return FileResponse("client/dashboard.html")


#PROXY APP -- PORT 8080
#intercepteaza si filtreaza tot traficul catre aplicatia protejata

proxy_app = FastAPI(title="WAF reverse proxy", lifespan=proxy_lifespan)

proxy_app.add_middleware(ProxyCSP)
proxy_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

proxy_app.include_router(proxy_router)

#MAIN == pornire servere
async def main():
    cfg = load_config()
    target_port = cfg.get("target_port", 3000)        
    
    # verificare --> backend ul trb sa ruleze pe target_port
    if not is_backend_running(target_port):
        print_instructions(target_port)
        print(f"\nNo backend detected on port {target_port} "
              f"read the instructions and start the WAF again :) \n")
        #sys.exit(1)
    
    print(f"Backend active on port {target_port}")
    
    dashboard_config = uvicorn.Config(
        app=dashboard_app,
        host="127.0.0.1",
        port=8000,
        log_level="warning",
    )

    proxy_config = uvicorn.Config(
        app=proxy_app,
        host="127.0.0.1",
        port=8080,
        log_level="warning",
    )

    print(f" Open WAF Dashboard   ->  http://127.0.0.1:8000")
    print(f" Reverse Proxy        ->  http://127.0.0.1:8080")

    await asyncio.gather(
        uvicorn.Server(dashboard_config).serve(),
        uvicorn.Server(proxy_config).serve(),
    )

if __name__ == "__main__":
    asyncio.run(main())


# workflow:
# 1. PORT=3000 npm start  (sau echivalent -> backend ruleaza pe target_port)
# 2. python main.py       (WAF detecteaza backendul si porneste)
