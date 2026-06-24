import pandas as pd
import numpy as np
# import matplotlib
# matplotlib.use('Agg')
# import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, accuracy_score

#indicators of compromise (utilizati si in regulile statice pt imbunatatirea detectiei) format sanitizat ca in BD
IOC = [
     # --- SQL injection ---
    "[union] [select]",      # union+select bracketed (forma sanitizata)
    "or 1[=]1",              # boolean tautology
    "'1'[=]'1",              # boolean tautology cu quote
    "admin'--",              # auth bypass cu commentariu SQL
    "admin' or",             # auth bypass varianta
    "'/*",                   # commentariu SQL bypass
    "sleep[(]",              # time-based MySQL/PostgreSQL
    "benchmark[(]",          # time-based MySQL
    "waitfor delay",         # time-based MSSQL
    "extractvalue[(]",       # error-based MySQL
    "updatexml[(]",          # error-based MySQL
    "substring[(]",          # blind SQL injection
    "drop table",            # destructiv
    "xp_cmdshell",           # MSSQL OS command exec
    "information_schema",    # enumerare metadata
    "mysql.user",            # enumerare credentiale
    # --- XSS ---
    "[<]script",
    "[<]img",
    "[<]svg",
    "[<]iframe",
    "[<]body",
    "[<]details",
    "onerror[=]",
    "onload[=]",
    "ontoggle[=]",
    "javascript:",
    "document.cookie",
    "alert[(]",
    # --- Path traversal ---
    "../",                   
    "..\\",                  
    "%2e%2e",               
    "%2f..",                 
    "%252f",                 
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    ".env",
    "windows/system32",
    "config/database",
    # --- Command injection ---
    "shell_exec",
    "|whoami",
    ";wget",
    ";curl",
    "$[(]id[)]",
    # --- Scanners ---
    "sqlmap", "nikto", "nmap", "wget/", "python-urllib", "curl/",
    "acunetix", "burp"
]

import os

data = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data_logs_ML.csv'))

relevant = (data[['timestamp', 'client_ip', 'field_a' ,'field_b', 'field_c', 'field_d', 'field_e']]
            .dropna(subset=['field_b', 'field_d', 'field_e'])
            .reset_index(drop=False))
check = data['is_anomaly']
n_total = len(relevant)
 
data_train = relevant.sample(frac=0.25, random_state=42)
remaining  = relevant.drop(index=data_train.index)              
data_test  = remaining.sample(n=int(0.10 * n_total), random_state=42)

data_train = data_train.reset_index(drop=True)
data_test  = data_test.reset_index(drop=True)

#feature engineering

#adaugarea coloanelor noi pe ambele seturi
def add_features(df, url_freq_map, ua_freq_map):
    d = df.copy()
    
    #lungime + nr aparitii url 
    d['url_length'] = d['field_b'].str.len()
    d['url_freq'] = d['field_b'].map(url_freq_map).fillna(0)

    #lungime + nr aparitii ua
    d['ua_length'] = d['field_d'].str.len()
    d['ua_freq'] = d['field_d'].map(ua_freq_map).fillna(0)
    
    #ioc?
    combined_b_d = (d['field_b'].fillna('') + ' ' + d['field_d'].fillna('')).str.lower()
    d['ioc_count'] = combined_b_d.apply(lambda t: sum(1 for p in IOC if p in t))
    d['has_ioc']   = (d['ioc_count'] > 0).astype(int)

    return d

url_freq_map = data_train['field_b'].value_counts()
ua_freq_map  = data_train['field_d'].value_counts()

#aplicarea pe train si test
data_train = add_features(
    data_train, url_freq_map, ua_freq_map
)
 
data_test = add_features(
    data_test, url_freq_map, ua_freq_map
)

#print(data_train.head())

#normalizarea datelor pt model
#categorical_cols = ['client_ip', 'field_b', 'field_c', 'field_d' ]
categorical_cols = [ 'field_c' ]
numeric_cols     = [
    'field_e',  # response time 
    'url_length', # lungime URL
    'url_freq',
    'ua_length',
    'ua_freq',                     
    'ioc_count', # nr indicatori de compromitere
    'has_ioc' # binar: exista IoC
]

#sunt selectate doar coloanele num valide // cele binare nu
valid_numeric_cols = [c for c in numeric_cols if data_train[c].nunique() > 1]

#fit_transform pe TRAIN pt a invata distributiile din setul de train
#one hot enc pt categorical 
ohe = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
#standard scaler pt numerice valide 
scaler = StandardScaler()
 
encoded_cat_train = ohe.fit_transform(data_train[categorical_cols])
scaled_num_train  = scaler.fit_transform(data_train[valid_numeric_cols])

#transform pe test (aplica distributiile din train)
encoded_cat_test  = ohe.transform(data_test[categorical_cols])
scaled_num_test   = scaler.transform(data_test[valid_numeric_cols])

df_cat_train = pd.DataFrame(encoded_cat_train, columns=ohe.get_feature_names_out(categorical_cols))
df_cat_test  = pd.DataFrame(encoded_cat_test,  columns=ohe.get_feature_names_out(categorical_cols))

df_num_train = pd.DataFrame(scaled_num_train,  columns=valid_numeric_cols)
df_num_test  = pd.DataFrame(scaled_num_test,   columns=valid_numeric_cols)

#df finale train + test
df_train_final = pd.concat([df_cat_train, df_num_train], axis=1)
df_test_final  = pd.concat([df_cat_test,  df_num_test],  axis=1)

#iso forest model (config + train)
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.03,                                     
    max_samples=256,
    max_features=0.9,
    random_state=42,
)
iso_forest.fit(df_train_final)

#calcul scoruri
#train set
predict_train       = iso_forest.predict(df_train_final)
anomaly_score_train = iso_forest.decision_function(df_train_final)

#test set
predict_test        = iso_forest.predict(df_test_final)
anomaly_score_test  = iso_forest.decision_function(df_test_final)


#evaluare scoruri (train / test)
data_analiza_train = data_train.copy()
data_analiza_train['anomaly_score'] = anomaly_score_train
data_analiza_train['anomaly'] = predict_train
 
data_analiza_test = data_test.copy()
data_analiza_test['anomaly_score'] = anomaly_score_test
data_analiza_test['anomaly'] = predict_test

#metrici etichetate
y_true_train = check.loc[data_train['index']].values
y_true_test = check.loc[data_test['index']].values

y_pred_train = (predict_train == -1).astype(int)
y_pred_test = (predict_test == -1).astype(int)
 
def print_metrics(split, y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    acc = accuracy_score(y_true, y_pred)
    p  = precision_score(y_true, y_pred, zero_division=0)
    r  = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    print(f"\n{'='*50}")
    print(f"  {split}")
    print(f"{'='*50}")
    print(f"  Accuracy   : {acc:.4f}")
    print(f"  Precision  : {p:.4f}")
    print(f"  Recall     : {r:.4f}")
    print(f"  F1-score   : {f1:.4f}")
    print(f"  TN={cm[0,0]:5d}  FP={cm[0,1]:4d}  FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
    return f1
 
f1_tr = print_metrics("TRAIN", y_true_train, y_pred_train)
f1_te = print_metrics("TEST",  y_true_test,  y_pred_test)
print(f"\n  {'OK' if f1_tr >= f1_te else 'nu e ok'} TRAIN F1 ({f1_tr:.4f}) >= TEST F1 ({f1_te:.4f})")

def retrain_from_parquet(archive_dir: str) -> dict:
    #citeste fisierele arhivate preia activity logs 
    #reantreneaza cu datele arhivate
    #returneaza dictionar cu noile obiecte + metrici de baza
   
    import glob
    import duckdb as _duckdb
 
    files = sorted(glob.glob(
        os.path.join(archive_dir, "fireball_archive_*.parquet")
    ))
    if not files:
        return {"error": "no_archives"}
    
    tmp = _duckdb.connect()
    frames = []
    for f in files:
        try:
            part = tmp.execute(
                "SELECT timestamp, client_ip, field_a, field_b, "
                "       field_c, field_d, field_e "
                f"FROM read_parquet('{f}') "
                "WHERE source_table = 'activity_logs'"
            ).df()
            frames.append(part)
        except (IOError, _duckdb.Error) as e:
            print(f"retraining stopped == corrupted archive {f} err-> {e}")
        finally:
            tmp.close()
 
    if not frames:
        return {"error": "no_data"}
 
    data = pd.concat(frames, ignore_index=True)
    data = data.dropna(subset=['field_b', 'field_d']).reset_index(drop=True)
 
    # field_e (varchar in parquet) == conversie float
    data['field_e'] = pd.to_numeric(data['field_e'], errors='coerce').fillna(0.0)
 
    # field_c e status_code string ("200", "403") == ALLOW/BLOCK
    def _to_action(v):
        try:
            return "BLOCK" if int(float(str(v))) in (401, 403) else "ALLOW"
        except Exception:
            return "ALLOW"
    data['field_c'] = data['field_c'].apply(_to_action)
 
    n = len(data)
    if n < 100:
        return {"error": "not_enough_data", "count": n}
 
    #esantionare 
    t = data.sample(frac=0.25, random_state=42)
    remaining = data.drop(index=t.index)
    te = remaining.sample(n=min(int(0.10 * n), len(remaining)), random_state=42)
    t = t.reset_index(drop=True)
    te = te.reset_index(drop=True)
 
    new_url_freq = t['field_b'].value_counts()
    new_ua_freq = t['field_d'].value_counts()
 
    t = add_features(t,  new_url_freq, new_ua_freq)
    te = add_features(te, new_url_freq, new_ua_freq)
 
    new_ohe = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    new_scaler = StandardScaler()
    new_valid = [c for c in numeric_cols if t[c].nunique() > 1]
 
    enc_t = new_ohe.fit_transform(t[categorical_cols])
    num_t = new_scaler.fit_transform(t[new_valid])
    X_t = pd.concat([
        pd.DataFrame(enc_t, columns=new_ohe.get_feature_names_out(categorical_cols)),
        pd.DataFrame(num_t, columns=new_valid)
    ], axis=1)
 
    new_iso = IsolationForest(
        n_estimators=100, contamination=0.03,
        max_samples=256, max_features=0.9, random_state=42,
    )
    new_iso.fit(X_t)
 
    # evaluare pe testul esantionat (rata de anomalii folosita ca proxy)
    enc_te = new_ohe.transform(te[categorical_cols])
    num_te = new_scaler.transform(te[new_valid].fillna(0))
    X_te = pd.concat([
        pd.DataFrame(enc_te, columns=new_ohe.get_feature_names_out(categorical_cols)),
        pd.DataFrame(num_te, columns=new_valid)
    ], axis=1)
    scores_te = new_iso.decision_function(X_te)
 
    return {
        "model":            new_iso,
        "ohe":              new_ohe,
        "scaler":           new_scaler,
        "url_freq_map":     new_url_freq,
        "ua_freq_map":      new_ua_freq,
        "valid_numeric":    new_valid,
        "train_rows":       len(t),
        "test_rows":        len(te),
        "anomaly_rate_pct": round(float((scores_te < 0).mean()) * 100, 2),
        "archive_count":    len(files),
    }

# import matplotlib.pyplot as plt
# from sklearn.metrics import ConfusionMatrixDisplay
 
# fig, ax = plt.subplots(1, 2, figsize=(9, 4))
# ConfusionMatrixDisplay.from_predictions(y_true_train, y_pred_train, ax=ax[0])
# ax[0].set_title('Train')
# ConfusionMatrixDisplay.from_predictions(y_true_test, y_pred_test, ax=ax[1])
# ax[1].set_title('Test')
# plt.tight_layout()
# #plt.show()
 
# # ---------- scatter: anomaly_score vs response_time ----------
# mask_n = (y_true_test == 0)
# mask_a = (y_true_test == 1)
 
# plt.figure(figsize=(10, 6))
# # normal: puncte verzi, mici, semi-transparente (fundal)
# plt.scatter(anomaly_score_test[mask_n], data_test.loc[mask_n, 'field_e'],
#             c='green', alpha=0.35, s=20, label='Trafic Normal')
# # anomalii: X-uri rosii, mai mari, cu contur negru (foreground)
# plt.scatter(anomaly_score_test[mask_a], data_test.loc[mask_a, 'field_e'],
#             c='red', marker='X', s=30, linewidths=0.6,
#             label='Anomalie')
# plt.xlabel('anomaly_score')
# plt.ylabel('response_time (ms)')
# plt.title('Cereri normale vs anomalii (test)')
# plt.legend()
# plt.show()
