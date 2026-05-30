
import os
import sys
import uuid
import random
import duckdb
import pandas as pd

#  CONFIG 
CSV_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "log_analyzer",
    "activity_logs_bun_diversified.csv",
)


DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fireball.db",
)

SAMPLE_FRAC               = None   # None = TOATE; 0.10 = 10%
CLEAR_TABLES              = True   # goleste activity_logs + firewall_actions inainte
POPULATE_FIREWALL_ACTIONS = True   # creeaza intrari in firewall_actions pentru BLOCK
BATCH_SIZE                = 500
SEED                      = 42

random.seed(SEED)

#  mapare status_code din field_c 
def derive_status_code(field_c: str) -> int:
    
    if str(field_c).strip().upper() == "BLOCK":
        
        return random.choices([403, 401, 429], weights=[0.70, 0.20, 0.10])[0]

    return random.choices([200, 304, 404, 500], weights=[0.88, 0.07, 0.04, 0.01])[0]


#  citire + sampling 
df = pd.read_csv(CSV_PATH)
if SAMPLE_FRAC is not None:
    df = df.sample(frac=SAMPLE_FRAC, random_state=SEED).reset_index(drop=True)

total = len(df)

print("Fireball WAF — DB populator (DuckDB)")
print(f"Source : {CSV_PATH}")
print(f"Target : {DB_PATH}")
print(f"Rows   : {total}")
print(f"Clear  : {CLEAR_TABLES}   |   Firewall actions: {POPULATE_FIREWALL_ACTIONS}")
print("─" * 52)

#  conectare 
db = duckdb.connect(DB_PATH)

if CLEAR_TABLES:
    # ordine: firewall_actions are FK logica catre activity_logs.log_id
    db.execute("DELETE FROM firewall_actions;")
    db.execute("DELETE FROM activity_logs;")

#  INSERT statements (DuckDB syntax) 
# `trigger` e cuvant rezervat -> il pun in ghilimele duble
INSERT_LOG = """
INSERT OR REPLACE INTO activity_logs
(log_id, timestamp, client_ip, http_method, request_path,
 status_code, user_agent, response_time_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
"""

INSERT_ACTION = """
INSERT OR REPLACE INTO firewall_actions
(action_id, timestamp, activity_log_id, rule_id, action_taken, "trigger")
VALUES (?, ?, ?, NULL, ?, ?);
"""

#  loop principal 
logs_batch    = []
actions_batch = []
ok = blocked = errors = 0

for i, row in df.iterrows():
    try:
        status = derive_status_code(row.get("field_c", "ALLOW"))
        rt     = row.get("field_e")
        rt     = float(rt) if pd.notna(rt) else None

        log_id = str(row["record_id"])
        ts     = str(row["timestamp"])

        logs_batch.append((
            log_id, ts,
            str(row["client_ip"]),
            str(row["field_a"]).upper(),     # http_method
            str(row["field_b"]),             # request_path
            int(status),
            str(row["field_d"]),             # user_agent
            rt,                              # response_time_ms
        ))

        if status == 403:
            blocked += 1
            if POPULATE_FIREWALL_ACTIONS:
                actions_batch.append((
                    f"act_{log_id}",         # deterministic -> REPLACE merge la re-rulare
                    ts, log_id,
                    "BLOCK",
                    "WAF_RULE_MATCH",        # placeholder; nu stim ce regula a apucat la generare
                ))
        else:
            ok += 1

        idx = i + 1
        if idx % 500 == 0 or idx == total:
            marker = "[BLOCK]" if status == 403 else "[OK]   "
            print(f"  {marker} {idx:4d}/{total}  {row['field_a']:6s}  {status}  {str(row['field_b'])[:55]}")

        # flush batch
        if len(logs_batch) >= BATCH_SIZE:
            db.executemany(INSERT_LOG, logs_batch)
            logs_batch.clear()
        if len(actions_batch) >= BATCH_SIZE:
            db.executemany(INSERT_ACTION, actions_batch)
            actions_batch.clear()

    except Exception as e:
        errors += 1
        print(f"  [ERR]  {i+1:4d}/{total}  {str(row.get('field_b',''))[:40]} — {e}")

# flush ce a ramas
if logs_batch:
    db.executemany(INSERT_LOG, logs_batch)
if actions_batch:
    db.executemany(INSERT_ACTION, actions_batch)

# ---------- verificare finala ---------------------------------------------
n_logs    = db.execute("SELECT COUNT(*) FROM activity_logs").fetchone()[0]
n_actions = db.execute("SELECT COUNT(*) FROM firewall_actions").fetchone()[0]
n_blocked_db = db.execute("SELECT COUNT(*) FROM activity_logs WHERE status_code = 403").fetchone()[0]

db.close()

print("─" * 52)
print(f"Procesate : OK={ok}  BLOCK={blocked}  ERR={errors}  TOTAL={total}")
print(f"In DB     : {n_logs} activity_logs ({n_blocked_db} cu status 403), {n_actions} firewall_actions")