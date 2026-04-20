import asyncio
import uuid
from datetime import datetime
from db.init_db import db, CACHE_IPS
from db.logger import firewall_actions_buffer
from db.init_db import add_new_rule
from .alert import sendMail

def block_and_log(ip: str, trigger: str, reason: str, current_time):
        CACHE_IPS.add(ip)

        new_rule_id = add_new_rule("Analyzer " + reason, "IP_MATCH", "IP", ip, action='BLOCK')
        
        firewall_actions_buffer.append((
            str(uuid.uuid4()), current_time, trigger,
            new_rule_id, "BLOCK", reason
        ))

        print(f"[WAF BLOCK] IP={ip} | trigger={trigger!r} | reason={reason} --> Rules updated!")

async def analyzer():
    
    #every threath has a specific query 
    #format == label, query, block threshold, template reason, label for trigger 

    analyzer_query_list = [
         
         # ! specific for the WAF 
         (
            "Repeated WAF Evasion",
            """
            SELECT al.client_ip, COUNT(*) AS blocked_count
            FROM firewall_actions fa
            JOIN activity_logs al ON fa.activity_log_id = al.log_id
            WHERE fa.action_taken = 'BLOCK'
            AND fa.timestamp >= NOW() - INTERVAL '10 minutes'
            GROUP BY al.client_ip
            HAVING COUNT(*) >= 5
            """,
            lambda row: f"{row[1]} repeated WAF blocks in 10min ",
            "waf_evasion_probe"
        ),

        #specific attack types
        (
            "Brute Force",
            """
            SELECT client_ip, COUNT(*) AS fail_count
            FROM activity_logs
            WHERE status_code IN (401, 403)
            AND timestamp >= NOW() - INTERVAL '5 minutes'
            GROUP BY client_ip
            HAVING COUNT(*) >= 10
            """,
            lambda row: f"{row[1]} failed auth attempts in 5min",
            "brute_force_auth"
        ),

        (
            "Automated Scanning Detection",
            """
            SELECT client_ip, COUNT(DISTINCT request_path) AS unique_404s
            FROM activity_logs
            WHERE status_code = 404
            AND timestamp >= NOW() - INTERVAL '1 minute'
            GROUP BY client_ip
            HAVING COUNT(DISTINCT request_path) >= 15
            """,
            lambda row: f"{row[1]} unique 404 paths in 1min (scanner)",
            "path_enumeration_scan"
        ),

        (
            "DDoS",
            """
            SELECT client_ip, COUNT(*) AS req_count
            FROM activity_logs
            WHERE timestamp >= NOW() - INTERVAL '1 minute'
            GROUP BY client_ip
            HAVING COUNT(*) >= 200
            """,
            lambda row: f"{row[1]} requests in 1min (rate abuse)",
            "ddos_rate_abuse"
        ),

        (
            "SQLi Probing",
            """
            SELECT al.client_ip, COUNT(*) AS sqli_hits
            FROM firewall_actions fa
            JOIN activity_logs al ON fa.activity_log_id = al.log_id
            JOIN rules r ON fa.rule_id = r.rule_id
            WHERE fa.action_taken = 'BLOCK'
            AND r.name LIKE '%SQL%'
            AND fa.timestamp >= NOW() - INTERVAL '30 minutes'
            GROUP BY al.client_ip
            HAVING COUNT(*) >= 3
            """,
            lambda row: f"{row[1]} SQLi attempts in 30min",
            "sqli_probe"
        ),

        (
            "XSS Probing",
            """
            SELECT al.client_ip, COUNT(*) AS xss_hits
            FROM firewall_actions fa
            JOIN activity_logs al ON fa.activity_log_id = al.log_id
            JOIN rules r ON fa.rule_id = r.rule_id
            WHERE fa.action_taken = 'BLOCK'
            AND r.name LIKE '%XSS%'
            AND fa.timestamp >= NOW() - INTERVAL '30 minutes'
            GROUP BY al.client_ip
            HAVING COUNT(*) >= 3
            """,
            lambda row: f"{row[1]} XSS attempts in 30min",
            "xss_probe"
        )
    ]

    while True:
        #runs every 60 seconds
        await asyncio.sleep(60)
        cursor = None 
    
        try: 
            cursor = db.cursor()
            current_time = datetime.now()

            for check_name, query, reason, trigger in analyzer_query_list:
                try: 
                      cursor.execute(query)
                      rows = cursor.fetchall()
                      for row in rows:
                           ip = row[0]
                           if ip not in CACHE_IPS:
                                block_and_log(ip, trigger, reason(row), current_time)
                                await sendMail("WAF ALERT", f"NEW --> {reason(row)} detected at {current_time.isoformat()}\n IP {ip} blocked!")
                except Exception as e:
                    print(f"[ERR analyzer][{check_name}] query failed = {e}")

        except Exception as e:
             print(f"[ERR] analyzer crashed bcs: {e}")
        finally:
             if cursor:
                cursor.close()
                    

