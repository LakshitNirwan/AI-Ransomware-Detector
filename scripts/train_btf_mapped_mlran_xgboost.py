import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset/processed/btf_mapped_mlran"
OUT = ROOT / "results/btf_mapped_mlran_reconstruction"
TARGET = "sample_type"
SEED = 42

train = pd.read_csv(DATA / "btf_mapped_mlran_train.csv")
test = pd.read_csv(DATA / "btf_mapped_mlran_test.csv")
features = [c for c in train.columns if c != TARGET]
y = train[TARGET].astype(int)
X = train[features].astype(np.float32)
X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=SEED, stratify=y)
constants = [c for c in features if X_train[c].nunique(dropna=False) <= 1]
features = [c for c in features if c not in constants]
X_train, X_val = X_train[features], X_val[features]
X_test = test[features].astype(np.float32)
y_test = test[TARGET].astype(int)
model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05, subsample=0.9,
    colsample_bytree=0.9, objective="binary:logistic", eval_metric="logloss",
    tree_method="hist", n_jobs=-1, random_state=SEED)
print("Training XGBoost...", flush=True)
model.fit(X_train, y_train)

def evaluate(X_part, y_part, split):
    pred = model.predict(X_part).astype(int)
    proba = model.predict_proba(X_part)[:, 1]
    return {"split": split, "accuracy": float(accuracy_score(y_part,pred)),
        "precision": float(precision_score(y_part,pred,zero_division=0)),
        "recall": float(recall_score(y_part,pred,zero_division=0)),
        "f1": float(f1_score(y_part,pred,zero_division=0)),
        "roc_auc": float(roc_auc_score(y_part,proba)),
        "confusion_matrix_labels_0_1": confusion_matrix(y_part,pred,labels=[0,1]).tolist()}

row = {"model":"xgboost", "train_rows":len(y_train), "validation_rows":len(y_val),
       "test_rows":len(y_test), "feature_count":len(features),
       "validation":evaluate(X_val,y_val,"validation"),
       "untouched_test":evaluate(X_test,y_test,"untouched_test")}
joblib.dump(model, OUT / "xgboost.joblib")
for name, X_part, y_part in (("validation",X_val,y_val),("test",X_test,y_test)):
    pred=model.predict(X_part).astype(int); proba=model.predict_proba(X_part)[:,1]
    pd.DataFrame({"y_true":y_part,"y_pred":pred,"probability_ransomware":proba}).to_csv(OUT/f"xgboost_{name}_predictions.csv",index=False)
metrics_path=OUT/"metrics.json"
info=json.loads(metrics_path.read_text(encoding="utf-8"))
info["models_run"].append("xgboost")
info["results"].append(row)
metrics_path.write_text(json.dumps(info,indent=2)+"\n",encoding="utf-8")
print(json.dumps(row,indent=2),flush=True)
