import asyncio
import httpx

PROXY_URL = "http://127.0.0.1:8080"
HEADERS_TEST = {"Analyzer-Test-Mode": "simulation"}


async def simulate_brute_force(client: httpx.AsyncClient):
    """Triggers: 10+ (401/403) from same IP in 5 min"""
    print("\n[SIM] Brute Force — hitting /login with bad creds (expect 401/403)")
    for i in range(12):
        resp = await client.post(f"{PROXY_URL}/login", data={"user": "admin", "password": "wrongpass{i}"})
        print(f"   attempt {i+1}: {resp.status_code}", end="\r")
    print(f"\n   done — 12 bad auth requests sent")

async def simulate_scanner(client: httpx.AsyncClient):
    """Triggers: 15+ distinct 404 paths in 1 min"""
    print("\n[SIM] Directory Scanner — hitting non-existent paths (expect 404)")
    fake_paths = [
        "/admin", "/.env", "/wp-config.php", "/phpmyadmin", "/backup.zip",
        "/.git/config", "/config.json", "/api/v1/users", "/secret",
        "/dashboard", "/panel", "/uploads/shell.php", "/server-status",
        "/api/keys", "/readme.txt", "/robots.txt", "/sitemap.xml"
    ]
    for path in fake_paths:
        resp = await client.get(f"{PROXY_URL}{path}")
        print(f"   {path}: {resp.status_code}", end="\r")
    print(f"\n   done — {len(fake_paths)} unique paths probed")

async def simulate_ddos(client: httpx.AsyncClient):
    """Triggers: 200+ requests in 1 min from same IP"""
    print("\n[SIM] DDoS / Rate Abuse — 210 rapid requests")
    tasks = [client.get(f"{PROXY_URL}/api/home?r={i}") for i in range(210)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    codes = [r.status_code if isinstance(r, httpx.Response) else "ERR" for r in results]
    print(f"   done — sent 210 requests | sample codes: {set(codes)}")

async def simulate_waf_evasion(client: httpx.AsyncClient):
    """Triggers: 5+ BLOCK hits in firewall_actions in 10 min (uses your existing regex rules)"""
    print("\n[SIM] WAF Evasion Probing — sending known-blocked payloads repeatedly")
    payloads = [
        "/../../../etc/passwd",
        "/%2e%2e%2fetc%2fpasswd",
        "/%252e%252e%252fwindows%252fwin.ini",
        "/%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
        "/..%5c..%5cwindows",
        "/..%00/etc/passwd",
    ]
    for payload in payloads:
        resp = await client.get(f"{PROXY_URL}{payload}")
        print(f"   {payload[:40]}: {resp.status_code}", end="\r")
    print(f"\n   done — {len(payloads)} evasion payloads sent")

async def simulate_sqli(client: httpx.AsyncClient):
    """Triggers: 3+ SQLi rule hits in 30 min"""
    print("\n[SIM] SQLi Probing — sending SQL injection payloads in query string")
    sqli_payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 UNION SELECT null,null,null--",
        "admin'--",
    ]
    for payload in sqli_payloads:
        resp = await client.get(f"{PROXY_URL}/api/users", params={"id": payload})
        print(f"   {payload[:30]}: {resp.status_code}", end="\r")
    print(f"\n   done — {len(sqli_payloads)} SQLi payloads sent")

async def simulate_xss(client: httpx.AsyncClient):
    """Triggers: 3+ XSS rule hits in 30 min"""
    print("\n[SIM] XSS Probing — sending XSS payloads")
    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
    ]
    for payload in xss_payloads:
        resp = await client.get(f"{PROXY_URL}/search", params={"q": payload})
        print(f"   {payload[:35]}: {resp.status_code}", end="\r")
    print(f"\n   done — {len(xss_payloads)} XSS payloads sent")

async def verify_block(client: httpx.AsyncClient, label: str):
    print(f"\n[CHECK] Verifying IP block after: {label}")
    try:
        resp = await client.get(f"{PROXY_URL}/api/home")
        if resp.status_code == 403:
            print(f"   {resp.status_code} [BLOCKED] Analyzer caught it!")
        else:
            print(f"   {resp.status_code} [NOT BLOCKED YET] — analyzer may not have run yet")
    except Exception as e:
        print(f"   Connection failed: {e}")

async def countdown(seconds: int, label: str):
    print(f"\n   Waiting {seconds}s for analyzer cycle ({label})...")
    for i in range(seconds, 0, -1):
        print(f"   {i}s remaining...   ", end="\r")
        await asyncio.sleep(1)
    print(f"   done waiting.         ")

async def main():
    print("#########################################################")
    print("  WAF ANALYZER SIMULATION  ")
    print("#########################################################")

    # Use a single client so all requests share the same source IP
    async with httpx.AsyncClient(timeout=10.0) as client:

        # Baseline
        resp = await client.get(f"{PROXY_URL}")
        print(f"\n[BASELINE] /api/home => {resp.status_code} (should be 200)")

        # --- Run all simulations ---
        await simulate_brute_force(client)
        await simulate_scanner(client)
        await simulate_sqli(client)
        await simulate_xss(client)
        await simulate_waf_evasion(client)
        await simulate_ddos(client)

        
        await countdown(65, "analyzer cycle")

        await verify_block(client, "all simulations")

    print("\n[DONE] Simulation complete.")
    

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest aborted.")