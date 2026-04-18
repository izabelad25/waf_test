import asyncio
import socket
import logging

#makes waf own the apps port
# - reads config file to get the port
# - tells the dev to open the app at port+1
# - waf proxy binds :3000 --> forw to :3001 
# - the protected app runs normally (waf gets the traffic first)

#NOTES !
# Node/Express -- pass PORT=3001 env var when starting the app
# Next.js --> next dev -p 3001

log = logging.getLogger("WAF.PortTakeover")

def get_internal_port(public_port: int) -> int:
    return public_port+1 #protected app runs this port internally
    
def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

def print_instructions(public_port: int, internal_port: int):
    print(r"""             +.+"+.+"+.+"+.+"+.+"+.+""")
    print(f"  WAF listening on  →  http://127.0.0.1:{public_port}")
    print(f"  Forwards to       →  http://127.0.0.1:{internal_port}")
    print()
    print(" ! Start your app on the INTERNAL port:")
    print(fr"""
                     ___________
                    ||"+.+"+.+"||            _______
                    ||FIREWALL ||           | _____ |
                    ||{public_port}.||           ||*____||
                    ||__"+.+"+_||           |  ___  |
                    |  + = = +  |           | |___*||
                        _|_|_   \           |       |
                       (_____)   \          |       |
                                  \    ___  | ~APP {internal_port}  |
                           ______  \__/   \_|       |
                          |   _  |      _/  |       |
                          |  ( ) |     /    |_______|
                          |___|__|    /         
                               \_____/
                    """)
    print(f"  Node/Express:  PORT={internal_port} node index.js")
    print(f"  Next.js:       next dev -p {internal_port}")
    print(f"  npm start:     PORT={internal_port} npm start")
    print()
    print(f"  Then open  http://localhost:{public_port}  as normal.")
    print(r"""             +.+"+.+"+.+"+.+"+.+"+.+""")
    

