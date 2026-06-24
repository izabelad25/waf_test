import socket

def is_backend_running(port: int, host: str = "127.0.0.1") -> bool:
    """
    verifica daca exista un serviciu activ care asculta pe (host, port)
    
     True == conexiunea TCP poate fi stabilita -> serviciul ruleaza.
     False  -> serviciul nu este disponibil.
    
     connect() pt verificare prezenta unui server activ
    
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def print_instructions(target_port: int):
    print(r"""             +.+"+.+"+.+"+.+"+.+"+.+""")
    print(f"  WAF forwarding on  →  http://127.0.0.1:{target_port}")
    print()
    print(" ! Start your app on the backend port:")
    print("Make sure the FRONTEND of your app forwards traffic to WAF port :8080")
    print(fr"""
                     ___________
                    ||"+.+"+.+"||            _______
                    ||FIREWALL ||           | _____ |
                    ||:8080   .||           ||*____||
                    ||__"+.+"+_||           |  ___  |
                    |  + = = +  |           | |___*||
                        _|_|_   \           |       |
                       (_____)   \          |       |
                                  \    ___  | ~APP {target_port}  |
                           ______  \__/   \_|       |
                          |   _  |      _/  |       |
                          |  ( ) |     /    |_______|
                          |___|__|    /         
                               \_____/
                    """)
    
    print("Start backend normally...")
    print(f"  Node/Express:  PORT={target_port} node index.js")
    print(f"  Next.js:       next dev -p {target_port}")
    print(f"  npm start:     PORT={target_port} npm start")
    print(r"""     +.+"+.+"+.+"+.+"+.+"+.+""")