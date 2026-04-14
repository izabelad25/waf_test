import asyncio
import uuid
from datetime import datetime
from db.init_db import db, CACHE_IPS
from db.logger import firewall_actions_buffer
from db.init_db import add_new_rule

def block_and_log(ip: str, trigger: str, reason: str, current_time):
        CACHE_IPS.add(ip)

        new_rule_id = add_new_rule("Analyzer " + reason, "IP_MATCH", "IP", ip, action='BLOCK')
        
        firewall_actions_buffer.append((
            str(uuid.uuid4()), current_time, reason,
            new_rule_id, "BLOCK", trigger
        ))

        print(f"[WAF BLOCK] IP={ip} | trigger={trigger!r} | reason={reason} --> Rules updated!")

async def analyzer():
    print("mr 305 analyzer active ! ")

    while True:
        #runs every 60 seconds
        await asyncio.sleep(60)
    
        try: 
            cursor = db.cursor()
            current_time = datetime.now()

            # functions for analyse that i need to implement ffs
            # for each func i need a specific query 

            # test func for brute force attacks
            brute_force_query = "SELECT '198.51.100.1' AS ip_address, 15 AS fail_count"

            cursor.execute(brute_force_query)
            brute_force_ips = cursor.fetchall()

            for row in brute_force_ips:
                ip, count = row 
                if ip not in CACHE_IPS:
                     block_and_log(ip, "Brute force detected", f"{count} login attemps in 5min", current_time)
        except Exception as e:
             print(f"[ERR] analyzer crashed bcs: {e}")
        finally:
             cursor.close()
                    

