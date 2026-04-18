#server
import asyncio
import uvicorn
import httpx

#env
import os
from dotenv import load_dotenv
load_dotenv()

#services
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware 

#background services
from db.logger import log_background_listener
from log_analyzer.analyze import analyzer
from log_analyzer.alert import sendMail

#routes
from routes.waf_rules import rule_router
from routes.network_logs import logs_router
from routes.waf_actions_log import waf_actions_router
from routes.reverse_proxy import proxy_router
from routes.waf_config import config_router, init_proxy_state, load_config, save_config, PROXY_STATE

#port binding + setup
from port_config import get_internal_port, is_port_free, print_instructions
import sys


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
dashboard_app.include_router(config_router)

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
    init_proxy_state()

    asyncio .create_task(log_background_listener())
    asyncio.create_task(analyzer())

    print(r"""       +.+"+.+"+.+"+.+"+.+"+.+""")
    print(r"""+.+"+.+"+.+"FIREWALL ACTIVE "+.+"+.+"+.+""")
    print(r"""       +.+"+.+"+.+"+.+"+.+"+.+""")

    #await sendMail("WAF ALERT", "NEW -->  test detected ")

    
@dashboard_app.on_event("shutdown")
async def shutdown_listener():
    
    print("F i r e b a l l #### shutdown")
    
# 2 SERVERS LAUNCHER
async def main():
    cfg = load_config()
    public_port = cfg.get("public_port", 3000)        
    internal_port = get_internal_port(public_port)      
    dashboard_port = 8000

    if not is_port_free(public_port):
        print(f"\nPort {public_port} is already in use.")
        print(f"your app is probably still running on {public_port}...")
        print(f"please read the instructions :) ")
        print(f"      WAF needs to own :{public_port} to intercept traffic.\n")
        sys.exit(1)
 
    print_instructions(public_port, internal_port)

    cfg["target_port"] = internal_port
    cfg["target_host"] = "localhost"

    
    save_config(cfg)
    PROXY_STATE["config"] = cfg
    PROXY_STATE["client"] = httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{internal_port}", timeout=15.0
    )



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

   
    print(f" Open Firewall Dashboard   ->  http://127.0.0.1:8000")
    #print(f"  Proxy               ->  http://127.0.0.1:8080")

    #test email alert
    

    await asyncio.gather(
        uvicorn.Server(dashboard_config).serve(),
        uvicorn.Server(proxy_config).serve(),
    )


if __name__ == "__main__":
    asyncio.run(main())
    
    

#workflow
# 1. python main.py
# 2. PORT=3001 npm start === app starts on internal port
# 3. open localhost:3000 (waf intercepts ++ app works normally)
