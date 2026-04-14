#server
import asyncio
import uvicorn

#services
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware 

#background services
from db.logger import log_background_listener
from log_analyzer.analyze import analyzer


#routes
from routes.waf_rules import rule_router
from routes.network_logs import logs_router
from routes.waf_actions_log import waf_actions_router
from routes.reverse_proxy import proxy_router



#UI dashboard app  PORT 8000
# !! proxy app on its separated port only

dashboard_app = FastAPI(title="Firewall - Dashboard")

#cors middleware 
dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

dashboard_app.include_router(rule_router)
dashboard_app.include_router(logs_router)
dashboard_app.include_router(waf_actions_router)

dashboard_app.mount("/client", StaticFiles(directory="client"), name="client")

@dashboard_app.get("/")
async def load_dashboard():
    return FileResponse("client/dashboard.html")

#PROXY app PORT 8080
#handles the requests and runs the waf engine

proxy_app = FastAPI(title="Fireball - proxy")

proxy_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

proxy_app.include_router(proxy_router)


#START

@dashboard_app.on_event("startup")
async def startup_listener():
    asyncio.create_task(log_background_listener())
    print("FIREWALL log batcher ACTIVE :P")

    asyncio.create_task(analyzer())
    print("Log Analyzer active! Dale!")


# 2 SERVERS LAUNCHER
async def main():
    dashboard_config = uvicorn.Config(
        app=dashboard_app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
    )

    proxy_config = uvicorn.Config(
        app=proxy_app,
        host="127.0.0.1",
        port=8080,
        log_level="info",
    )

    dashboard_server = uvicorn.Server(dashboard_config)
    proxy_server = uvicorn.Server(proxy_config)

    print("#"*55)
    print(" FIREBALL ")
    print(f"  Dashboard  ->  http://127.0.0.1:8000")
    print(f"  Proxy      ->  http://127.0.0.1:8080  (point your app here)")
    print("#" * 55)


    await asyncio.gather(
        dashboard_server.serve(),
        proxy_server.serve(),
    )

if __name__ == "__main__":
    asyncio.run(main())


