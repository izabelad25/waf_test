import asyncio
import socket
import sys
import logging

log = logging.getLogger("WAF.PortGuard")
 
_guard_server: asyncio.AbstractServer | None = None
 
 
async def _handle_blocked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Respond to any direct connection with a plain 403 and close."""
    try:
        await reader.read(4096)          # drain the request bytes
    except Exception:
        pass
    try:
        writer.write(
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"X-Blocked-By: FireballWAF\r\n\r\n"
            b"Direct access blocked. \n"
        )
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()
 
 
async def start_guard(app_port: int) -> bool:
    
    global _guard_server
 
    if sys.platform == "win32":
        log.warning(
            "Windows detected: port guard is informational only. "
            "Manually ensure nothing hits :%d directly.", app_port
        )
        return False
 

    #linux
    try:
        _guard_server = await asyncio.start_server(
            _handle_blocked,
            host="127.0.0.1",
            port=app_port,
            reuse_address=False,
            reuse_port=False,
        )
        log.info("Port guard active on :%d — direct access blocked.", app_port)
        return True
    except OSError as e:
        log.warning(
            "Could not bind guard on :%d (%s). "
            "Make sure the real app is stopped before starting the WAF "
            "if you want full interception.", app_port, e
        )
        return False
 
 
async def stop_guard():
    global _guard_server
    if _guard_server:
        _guard_server.close()
        await _guard_server.wait_closed()
        _guard_server = None
        log.info("Port guard released.")