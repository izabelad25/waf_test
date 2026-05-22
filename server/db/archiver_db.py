#background service 
#monitors fireball.db size and archives old rows from activity_logs and firewall_actions

#db file threshold == 200mb
#when it reaches the limit it archives the old rows into a compressed PARQUET archive 

#background service (runs every 5 min)
#archive format == Parquet (duckDB can write it natively)
#archive location == same dir as fireball.db (fireball_archive_YYYYMMDD_HHMMSS.parquet)
#1 file / run

#after export --> old rows are deleted from the db 

import asyncio
import os
import sys
from datetime import datetime, timedelta

#paths (pyInstaller safe)
_BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(os.path.dirname(_BASE), "fireball.db")
ARCHIVE_DIR = os.path.dirname(DB_PATH)

#constants (modificare necesara pt user sa poata ajusta parametrii)
SIZE_THRESHOLD_MB = 200
ARCHIVE_OLDER_THAN_DAYS = 7 #rows older than 7 days are achived automatically
CHECK_INTERVAL_SECONDS = 300 #seconds == 5 mins 
MIN_ROWS_TO_ARCHIVE = 100 #if less than 100 rows qualify it won't run

#functions
def db_size_mb() -> float:
    #returns the currrent size of the db file in mb
    try:
        return os.path.getsize(DB_PATH) / (1024*1024)
    except FileNotFoundError:
        return 0.0

def archive_path(stamp: str)->str:
    #builds the output Parquet file for the archiving run
    filename = f"fireball_archive_{stamp}.parquet"
    return os.path.join(ARCHIVE_DIR, filename)

def build_archive(cutoff: datetime, archive_file: str)-> dict:
    #archiving work is synchronous 
    #1= count rows that qualify in both tables
    #2= export them to a Parquet file ("source_table" added)
    #3= delete exported rows from db
    #4= vacuum db to reclaim disk space
    #  returns a summary dict w counts and file size

    import duckdb

    conn = duckdb.connect(DB_PATH)
    try:
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        #1=count rows to archive 
        log_count = conn.execute(
            "SELECT COUNT(*) FROM activity_logs WHERE timestamp < ?",
            [cutoff_str]
        ).fetchone()[0]
 
        action_count = conn.execute(
            "SELECT COUNT(*) FROM firewall_actions WHERE timestamp < ?",
            [cutoff_str]
        ).fetchone()[0]

        total = log_count + action_count

        if total < MIN_ROWS_TO_ARCHIVE:
            return {
                "skipped": True,
                "reason": f"only {total} rows qualify (minimum {MIN_ROWS_TO_ARCHIVE})",
                "log_rows": log_count,
                "action_rows": action_count,
            }
        
        #2=export to parquet
        #duckDB writes columnar compressed parquet
        conn.execute(f"""
            COPY (
                SELECT
                    'activity_logs'     AS source_table,
                    log_id              AS record_id,
                    timestamp,
                    client_ip,
                    http_method         AS field_a,
                    request_path        AS field_b,
                    CAST(status_code AS VARCHAR)  AS field_c,
                    user_agent          AS field_d,
                    CAST(response_time_ms AS VARCHAR) AS field_e,
                    NULL                AS field_f
                FROM activity_logs
                WHERE timestamp < '{cutoff_str}'
 
                UNION ALL
 
                SELECT
                    'firewall_actions'  AS source_table,
                    action_id           AS record_id,
                    timestamp,
                    NULL                AS client_ip,
                    action_taken        AS field_a,
                    trigger             AS field_b,
                    CAST(rule_id AS VARCHAR) AS field_c,
                    activity_log_id     AS field_d,
                    NULL                AS field_e,
                    NULL                AS field_f
                FROM firewall_actions
                WHERE timestamp < '{cutoff_str}'
            )
            TO '{archive_file}'
            (FORMAT PARQUET, COMPRESSION ZSTD)
        """)

        #3=delete rows archived as 1 transaction (if 1 fails both fail)
        conn.execute("BEGIN TRANSACTION")
        try:
            conn.execute(
                "DELETE FROM activity_logs WHERE timestamp < ?", [cutoff_str]
            )
            conn.execute(
                "DELETE FROM firewall_actions WHERE timestamp < ?", [cutoff_str]
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            #remove the parquet file created if something goes wrong
            if os.path.exists(archive_file):
                try:
                    os.remove(archive_file)
                except OSError:
                    pass
            raise

        #4= checkpoint==vacuum 
        conn.execute("CHECKPOINT")

        #archive is small (transforming mb to kb)
        archive_size_kb = os.path.getsize(archive_file)/1024

        return{
            "skipped":      False,
            "archive_file": archive_file,
            "log_rows":     log_count,
            "action_rows":  action_count,
            "total_rows":   total,
            "archive_kb":   round(archive_size_kb, 1),
        }
    
    except Exception as e:
        #if parquet file fails it rollsback the data it archived
        if os.path.exists(archive_file):
            try:
                os.remove(archive_file)
            except OSError:
                pass
            raise e
    
    finally:
        conn.close()

#async function that will be called in the main program 
async def archiver():
    #scheduled
    print(
        " DB ARCHIVER started...parameters are being checked for optimising disk space.. "
          f"threshold={SIZE_THRESHOLD_MB} MB, "
          f"cutoff={ARCHIVE_OLDER_THAN_DAYS} days, "
          f"interval={CHECK_INTERVAL_SECONDS}s"
    )

    while True:
        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
        try:
            size_mb = db_size_mb()
            if size_mb < SIZE_THRESHOLD_MB:
                print(f"DB size = {size_mb:.1f} MB  (threshold {SIZE_THRESHOLD_MB} MB) = no action needed")
                continue
            print(f"DB size = {size_mb:.1f} MB = threshold exceeded, starting archive run...")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_file = archive_path(stamp)
            cutoff = datetime.now()-timedelta(days=ARCHIVE_OLDER_THAN_DAYS)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, build_archive, cutoff, archive_file)

            if result.get("skipped"):
                print(f"DB ARCHIVER Skipped because == {result['reason']}")
            else:
                new_size_mb = db_size_mb()
                print(
                    f"DB Archive complete:\n"
                    f"           file       = {result['archive_file']}\n"
                    f"           rows moved = {result['total_rows']:,}  "
                    f"({result['log_rows']:,} logs + {result['action_rows']:,} actions)\n"
                    f"           parquet    = {result['archive_kb']} KB\n"
                    f"           DB size    = {size_mb:.1f} MB → {new_size_mb:.1f} MB"
                )
        except Exception as e:
            print(f"DB ARCHIVER ERROR during archiving --> exception --> {e}")
