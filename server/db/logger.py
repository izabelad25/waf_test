import asyncio
from datetime import datetime
from db.init_db import db

#BUFFER == temp storage
activity_logs_buffer = []
firewall_actions_buffer = []

#function for writing the batches to DUCKdb
def logs_writer():
    global activity_logs_buffer, firewall_actions_buffer

    if not activity_logs_buffer and not firewall_actions_buffer:
        return
    
    try:
        if activity_logs_buffer:
            db.executemany("INSERT INTO activity_logs " \
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", activity_logs_buffer)
            activity_logs_buffer.clear()
        
        if firewall_actions_buffer:
            db.executemany("INSERT INTO firewall_actions " \
            "VALUES (?, ?, ?, ?, ?, ?)", firewall_actions_buffer)
            firewall_actions_buffer.clear()
    except Exception as e:
        print(f"Error in writing log batches to DB: {e}")

#background function == runs the writer every second == avoids db crash
async def log_background_listener():
    while True:
        await asyncio.sleep(1)
        logs_writer()