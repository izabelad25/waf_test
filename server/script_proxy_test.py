import asyncio
import httpx

PROXY_URL = "http://127.0.0.1:8080"

async def main():
    print(f"spamez proxy ul")

    async with httpx.AsyncClient() as client:
        #test clean 
        print("CLEAN TEST")
        resp = await client.get(f"{PROXY_URL}/api/home")
        print(f"   Result: {resp.status_code} (Expected: 200 OK)\n")

        print(" ! ANALYZER TESTS ! ")
        for i in range(1,16):
            resp = await client.get(f"{PROXY_URL}/login?attempt={i}")
            print(f"   Attempt {i}: {resp.status_code}", end="\r")
        
        print("wait...")
        for i in range(65, 0, -1):
            print(f"    {i} seconds...", end="\r")
            await asyncio.sleep(1)

        print("\n\n TEST ##### Verifying the IP Block ####")
        
        try:
            resp = await client.get(f"{PROXY_URL}/api/home")
            if resp.status_code == 403:
                print(f"   Result: {resp.status_code}  [SUCCESS] Mr. 305 blocked your IP in the background!")
            else:
                print(f"   Result: {resp.status_code}  [FAILED] The WAF let us through.")
        except Exception as e:
            print(f"   Result: Connection failed ({e}).  WAF gone!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTest aborted.")
