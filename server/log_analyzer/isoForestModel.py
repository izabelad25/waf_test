import pandas as pd
import numpy as np
# import matplotlib
# matplotlib.use('Agg')
# import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

#indicators of compromise (utilizati si in regulile statice pt imbunatatirea detectiei)
IOC = [
    "union select", "' or ", "sleep(", "xp_cmd", "<script",
    "onerror=", "onload=", "../", "etc/passwd", "etc/shadow",
    ".env", "shell_exec",
    "sqlmap", "nikto", "nmap", "wget", "python-urllib", "curl/",
]

import os
data = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'activity_logs_synthetic_final.csv'))

#din date se elimina randurile care au valori lipsa pt URL / USER AGENT / response TIME 
data_train = (data[data['dataset_split'] == 'train']
              .dropna(subset=['field_b', 'field_d', 'field_e'])
              .copy().reset_index(drop=True))
data_test  = (data[data['dataset_split'] == 'test']
              .dropna(subset=['field_b', 'field_d', 'field_e'])
              .copy().reset_index(drop=True))

#feature engineering
#pe setul de train

#referinta statistica folosita == BOX PLOT
# IQR = Q3 - Q1
# limita superioara = q3 + 1.5* iqr
# limita inferioara = q1 - 1.5* iqr
#aplicare pe fiecare variabila calculata din campurile utilizate
#   url_length = outlier sus === anomalie
#   resp_time = outlier sus === anomalie
#   ip_uniq_path = outlier sus === anomalie
#   url_freq = sub q1 (direct sub q1 pt ca pe datele reale q1-1.5*iqr < 0)
#   ua_freq = sub q1 

#timp raspuns / url 
_rt_grp        = data_train.groupby('field_b')['field_e']
train_path_q3  = _rt_grp.quantile(0.75)
train_path_iqr = (_rt_grp.quantile(0.75) - _rt_grp.quantile(0.25)).clip(lower=1)

#timp raspuns global (fallback pt url uri noi in test)
train_rt_q3    = data_train['field_e'].quantile(0.75)
train_rt_iqr   = data_train['field_e'].quantile(0.75) - data_train['field_e'].quantile(0.25)

#frecventa url
train_url_freq    = data_train['field_b'].value_counts()
train_url_freq_q1 = train_url_freq.quantile(0.25)

#frecventa user agent
train_ua_freq    = data_train['field_d'].value_counts()
train_ua_freq_q1 = train_ua_freq.quantile(0.25)

#lungime URL
_url_lens           = data_train['field_b'].str.len()
train_url_len_q3    = _url_lens.quantile(0.75)
train_url_len_iqr   = _url_lens.quantile(0.75) - _url_lens.quantile(0.25)

#cai url distincte / ip
_ip_uniq             = data_train.groupby('client_ip')['field_b'].nunique()
train_ip_uniq_paths  = _ip_uniq
train_ip_uniq_q3     = _ip_uniq.quantile(0.75)
train_ip_uniq_iqr    = _ip_uniq.quantile(0.75) - _ip_uniq.quantile(0.25)


#aplicarea rezultatelor statisticilor din train pe ambele setul si construirea variabilelor noi in ambele seturi
def add_features(df, path_q3, path_iqr, rt_q3, rt_iqr, url_freq, url_freq_q1,
                 ua_freq, ua_freq_q1, url_len_q3, url_len_iqr,
                 ip_uniq_paths, ip_uniq_q3, ip_uniq_iqr):
    d = df.copy()
    #lungimea url ului
    d['url_length'] = d['field_b'].str.len()
    #calcul limita 
    url_upper = url_len_q3 + 1.5 * url_len_iqr
    d['url_len_deviation'] = (d['url_length'] - url_upper).clip(lower=0)
    d['url_len_outlier']   = (d['url_length'] > url_upper).astype(int) #1 daca depaseste BINAR

    #frecventa url
    d['url_frequency'] = d['field_b'].map(url_freq).fillna(1) #url uri nevazute in train primesc by default valoarea 1
    d['url_freq_low_outlier'] = (d['url_frequency'] < url_freq_q1).astype(int) #1 daca este sub q1

    #frecventa user-agent  acc logica aplicata
    d['user_agent_frequency'] = d['field_d'].map(ua_freq).fillna(1)
    d['ua_freq_low_outlier']  = (d['user_agent_frequency'] < ua_freq_q1).astype(int)

    #timp raspuns
    rt_upper = (
        d['field_b'].map(path_q3).fillna(rt_q3) +
        1.5 * d['field_b'].map(path_iqr).fillna(rt_iqr)
    )
    d['response_time_deviation'] = (d['field_e'] - rt_upper).clip(lower=0)
    d['rt_outlier'] = (d['field_e'] > rt_upper).astype(int)

    #cai url unice / ip
    d['ip_unique_paths'] = d['client_ip'].map(ip_uniq_paths).fillna(1)
    ip_upper = ip_uniq_q3 + 1.5 * ip_uniq_iqr
    d['ip_path_deviation'] = (d['ip_unique_paths'] - ip_upper).clip(lower=0)
    d['ip_path_outlier']   = (d['ip_unique_paths'] > ip_upper).astype(int)

    #ioc
    combined       = (d['field_b'].fillna('') + ' ' + d['field_d'].fillna('')).str.lower()
    d['ioc_count'] = combined.apply(lambda t: sum(1 for p in IOC if p in t))
    d['has_ioc']   = (d['ioc_count'] > 0).astype(int)

    #waf action
    d['is_blocked'] = d['field_c'].map({'BLOCK': 1, 'ALLOW': 0}).fillna(0).astype(int)

    return d

#aplicarea pe train si test
data_train = add_features(
    data_train,
    train_path_q3,    train_path_iqr,
    train_rt_q3,      train_rt_iqr,
    train_url_freq,   train_url_freq_q1,
    train_ua_freq,    train_ua_freq_q1,
    train_url_len_q3, train_url_len_iqr,
    train_ip_uniq_paths, train_ip_uniq_q3, train_ip_uniq_iqr,
)
 
data_test = add_features(
    data_test,
    train_path_q3,    train_path_iqr,
    train_rt_q3,      train_rt_iqr,
    train_url_freq,   train_url_freq_q1,
    train_ua_freq,    train_ua_freq_q1,
    train_url_len_q3, train_url_len_iqr,
    train_ip_uniq_paths, train_ip_uniq_q3, train_ip_uniq_iqr,
)

#normalizarea datelor pt model
categorical_cols = ['field_b', 'field_d']
numeric_cols     = [
    'field_e',                 # response time 
    'url_length',              # lungime URL 
    'url_len_deviation',       # exces peste Q3 + 1.5*IQR lungime box plot
    'url_len_outlier',         # binar: URL depaseste Q3 + 1.5*IQR
    'url_frequency',           # frecventa URL in train
    'url_freq_low_outlier',    # binar: URL sub Q1 frecventa
    'user_agent_frequency',    # frecventa UA in train
    'ua_freq_low_outlier',     # binar: UA sub Q1 frecventa
    'response_time_deviation', # exces RT peste Q3_url + 1.5*IQR_url box plot
    'rt_outlier',              # binar: RT depaseste Q3_url + 1.5*IQR_url
    'ip_unique_paths',         # nr cai unice per IP
    'ip_path_deviation',       # exces peste Q3 + 1.5*IQR cai per IP box plot
    'ip_path_outlier',         # binar: IP depaseste Q3 + 1.5*IQR
    'ioc_count',               # nr indicatori de compromitere
    'has_ioc',                 # binar: exista IoC
    'is_blocked',              # binar: WAF a blocat
]

#sunt selectate doar coloanele num valide // cele binare nu
valid_numeric_cols = [c for c in numeric_cols if data_train[c].nunique() > 1]

#fit_transform pe TRAIN pt a invata distributiile din setul de train
#one hot enc pt categorical 
ohe    = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
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
    contamination=0.01,                                    # 1% anomalii in train 
    max_samples=max(256, int(len(df_train_final) * 0.25)), # 25% adaptiv 
    random_state=42,
)
iso_forest.fit(df_train_final)

#calcul scoruri
#train set
anomaly_score_train = iso_forest.decision_function(df_train_final)
predict_train       = iso_forest.predict(df_train_final)
#test set
anomaly_score_test  = iso_forest.decision_function(df_test_final)
predict_test        = iso_forest.predict(df_test_final)

#evaluare scoruri (train / test)
data_analiza_train = data_train.copy()
data_analiza_train['anomaly_score'] = anomaly_score_train
data_analiza_train['anomaly']       = predict_train
 
data_analiza_test = data_test.copy()
data_analiza_test['anomaly_score'] = anomaly_score_test
data_analiza_test['anomaly']       = predict_test


#metrici etichetate
y_true_train = data_train['is_anomaly'].values
y_true_test  = data_test['is_anomaly'].values
y_pred_train = (predict_train == -1).astype(int)
y_pred_test  = (predict_test  == -1).astype(int)
 
def print_metrics(split, y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    p  = precision_score(y_true, y_pred, zero_division=0)
    r  = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    print(f"\n{'='*50}")
    print(f"  {split}")
    print(f"{'='*50}")
    print(f"  Precision  : {p:.4f}")
    print(f"  Recall     : {r:.4f}")
    print(f"  F1-score   : {f1:.4f}")
    print(f"  TN={cm[0,0]:5d}  FP={cm[0,1]:4d}  FN={cm[1,0]:4d}  TP={cm[1,1]:4d}")
    return f1
 
f1_tr = print_metrics("TRAIN", y_true_train, y_pred_train)
f1_te = print_metrics("TEST",  y_true_test,  y_pred_test)
print(f"\n  {'✓' if f1_tr >= f1_te else '✗'} TRAIN F1 ({f1_tr:.4f}) >= TEST F1 ({f1_te:.4f})")

