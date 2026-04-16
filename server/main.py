#server
import asyncio
import uvicorn

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
from port_bind import start_guard, stop_guard
from log_analyzer.analyze import analyzer
from log_analyzer.alert import sendMail

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
    print(r"""             +.+"+.+"+.+"+.+"+.+"+.+""")
    print(r"""+.+"+.+"+.+"FIREWALL log batcher ACTIVE "+.+"+.+"+.+""")
    print(r"""             +.+"+.+"+.+"+.+"+.+"+.+""")
    

    asyncio.create_task(analyzer())
    print(r"""              +.+"+.+"+.+"+.+"+.+"+.+""")
    print(r"""+.+"+.+"+.+"FIREWALL log analyzer ACTIVE "+.+"+.+"+.+""")
    print(r"""              +.+"+.+"+.+"+.+"+.+"+.+""")

    #await sendMail("WAF ALERT", "NEW -->  test detected ")

    await start_guard(3000) #direct access to port 3000 denied


@dashboard_app.on_event("shutdown")
async def shutdown_listener():
    await stop_guard()
    print("F i r e b a l l #### shutdown")
    

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

    
    
    print(r"""
                     ___________
                    ||"+.+"+.+"||            _______
                    ||         ||           | _____ |
                    ||FIREWALL.||           ||*____||
                    ||__"+.+"+_||           |  ___  |
                    |  + = = +  |           | |___*||
                        _|_|_   \           |       |
                       (_____)   \          |       |
                                  \    ___  | ~WEB  |
                           ______  \__/   \_|       |
                          |   _  |      _/  |       |
                          |  ( ) |     /    |_______|
                          |___|__|    /         
                               \_____/
                    """)
    print(f"  Firewall Dashboard  ->  http://127.0.0.1:8000")
    print(f"  Proxy               ->  http://127.0.0.1:8080")

    #test email alert
    
    
    
    await asyncio.gather(
        dashboard_server.serve(),
        proxy_server.serve(),
    )

    

if __name__ == "__main__":
    asyncio.run(main())
    
    


