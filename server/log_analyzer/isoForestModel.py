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
     "union [select]", "or 1[=]1", "sleep[(]", "xp_cmd",
    "[<]script", "onerror[=]", "onload[=]", "[.].[.]/",
    "etc/passwd", "etc/shadow", ".env", "shell_exec",
    "sqlmap", "nikto", "nmap", "wget", "python-urllib", "curl/"
]

import os

data = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'activity_logs_synthetic_final_final.csv'))

relevant = (data[['field_b', 'field_d', 'field_e']]
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

#normalizarea datelor pt model
categorical_cols = ['field_b', 'field_d']
numeric_cols     = [
    'field_e',                 # response time 
    'url_length',               # lungime URL
    'url_freq',
    'ua_length',
    'ua_freq',                     
    'ioc_count',               # nr indicatori de compromitere
    'has_ioc',                 # binar: exista IoC
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
    contamination=0.03,                                     
    max_samples=max(256, int(len(df_train_final) * 0.25)),  
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
data_analiza_train['anomaly']       = predict_train
 
data_analiza_test = data_test.copy()
data_analiza_test['anomaly_score'] = anomaly_score_test
data_analiza_test['anomaly']       = predict_test


#metrici etichetate
y_true_train = check.loc[data_train['index']].values
y_true_test  = check.loc[data_test['index']].values

y_pred_train = (predict_train == -1).astype(int)
y_pred_test  = (predict_test  == -1).astype(int)
 
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

