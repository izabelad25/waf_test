import os
import numpy as np
import pandas as pd

import importlib.util, sys
 
_HERE = os.path.dirname(os.path.abspath(__file__))
 
spec = importlib.util.spec_from_file_location(
    "isoForestModel",
    os.path.join(_HERE, "isoForestModel.py")
)
_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_mod)

#obiectele antrenate pe train set
_ISO = _mod.iso_forest
_OHE = _mod.ohe
_SCALER = _mod.scaler

#statisticile pe care e antrenat

_TRAIN_URL_FREQ = _mod.url_freq_map

_TRAIN_UA_FREQ = _mod.ua_freq_map

_CAT_COLS = _mod.categorical_cols
_VALID_NUM = _mod.valid_numeric_cols

def run_scan(db) -> dict:
   #preia datele din db si ruleaza modelul pe date
    rows = db.execute(
        """
        SELECT log_id, timestamp, client_ip, http_method,
               request_path, status_code, user_agent, response_time_ms
        FROM activity_logs
        ORDER BY timestamp DESC
        LIMIT 2000
        """
    ).fetchall()
 
    if len(rows) < 20:
        return {"error": "not_enough_data", "count": len(rows)}
 
    df = pd.DataFrame(rows, columns=[
        "log_id", "timestamp", "client_ip", "http_method",
        "request_path", "status_code", "user_agent", "response_time_ms"
    ])
 
    #df["timestamp"]        = pd.to_datetime(df["timestamp"], errors="coerce")
    #df = df.rename(columns={"response_time_ms": "field_e"})  
    #df["status_code"]      = pd.to_numeric(df["status_code"], errors="coerce").fillna(200).astype(int)
    df["request_path"]     = df["request_path"].fillna("/").astype(str)
    df["user_agent"]       = df["user_agent"].fillna(" ").astype(str)
    df["client_ip"]        = df["client_ip"].fillna(" ").astype(str)
   
 
    #redenumire coloane
    df = df.rename(columns={
        "http_method": "field_a",
        "request_path":     "field_b",
        
        "user_agent":       "field_d",
        "response_time_ms": "field_e",
    })

    df["field_c"] = np.where(df["status_code"].isin([401, 403]), "BLOCK", "ALLOW")
    df["is_blocked"] = df["status_code"].isin([401, 403]).astype(int)
 
    #adaugare features
    df = _mod.add_features(
        df,
        _TRAIN_URL_FREQ, 
        _TRAIN_UA_FREQ
      
    )
 
    # ohe si fit transform antrenate din model
    cat_cols = _CAT_COLS
    enc_arr  = _OHE.transform(df[cat_cols])
    enc_df   = pd.DataFrame(enc_arr, columns=_OHE.get_feature_names_out(cat_cols), index=df.index)
    num_df   = pd.DataFrame(_SCALER.transform(df[_VALID_NUM].fillna(0)), columns=_VALID_NUM, index=df.index)
    X        = pd.concat([enc_df, num_df], axis=1)
 
    #utilizare model
    scores  = _ISO.decision_function(X)
    #threshold default 0.00
    predict = np.where(scores < 0, -1, 1)
    
    df["if_score"]   = scores
    df["is_anomaly"] = (predict == -1).astype(int)
 
    #rezultate pt dashboard
    anomalies = df[df["is_anomaly"] == 1].sort_values("if_score").head(100)
 
    normals   = df[df["is_anomaly"] == 0].sample(min(500, int((df["is_anomaly"]==0).sum())), random_state=42)
    scatter   = pd.concat([normals, anomalies])
 
    scatter_points = [
        {
            "x":       float(r["if_score"]),
            "y":       float(r["field_e"]),
            "anomaly": int(r["is_anomaly"]),
            "ip":      str(r["client_ip"]),
            "path":    str(r["field_b"])[:60],
        }
        for _, r in scatter.iterrows()
    ]
 
    anomaly_list = [
        {
            "log_id":           str(r["log_id"]),
            "timestamp":        r["timestamp"].isoformat() if pd.notna(r["timestamp"]) else None,
            "client_ip":        str(r["client_ip"]),
            "http_method":      str(r["field_a"]),
            "request_path":     str(r["field_b"]),
            "status_code":      int(r["status_code"]),
            "user_agent":       str(r["field_d"]),
            "response_time_ms": float(r["field_e"]),
            "if_score":         round(float(r["if_score"]), 5),
            "ioc_count":        int(r["ioc_count"]),
            "is_blocked":       int(r["is_blocked"]),
        }
        for _, r in anomalies.iterrows()
    ]
 
    return {
        "total_scanned":   int(len(df)),
        "anomalies_found": int(df["is_anomaly"].sum()),
        "scatter_points":  scatter_points,
        "anomalies":       anomaly_list,
    }