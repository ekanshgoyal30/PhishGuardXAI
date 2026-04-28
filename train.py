"""
PhishGuard ML Training Pipeline
Run: py train.py
"""

import sys, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, f1_score, precision_score, recall_score)
import xgboost as xgb
import shap
import warnings
warnings.filterwarnings("ignore")

from data.generate_dataset import build_dataset
from models.feature_extractor import extract_features, get_feature_names

DATA_DIR   = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(DATA_DIR,   exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

print("=" * 60)
print("PhishGuard XAI - Training Pipeline")
print("=" * 60)

print("\n[1/6] Building dataset...")
df = build_dataset()
df.to_csv(os.path.join(DATA_DIR, "emails.csv"), index=False)

print("\n[2/6] Extracting features...")

def safe_extract(row):
    try:
        return extract_features(
            str(row.get("subject", "")),
            str(row.get("sender", "")),
            str(row.get("body", ""))
        )
    except Exception as e:
        print(f"  Warning: {e}")
        return {k: 0 for k in get_feature_names()}

features_list = df.apply(safe_extract, axis=1).tolist()
X = pd.DataFrame(features_list)
y = df["label"].values

feature_names = list(X.columns)
print(f"  Features: {len(feature_names)}")
print(f"  Samples:  {len(X)}")
print(f"  Class balance: {y.mean()*100:.1f}% phishing")

with open(os.path.join(MODELS_DIR, "feature_names.json"), "w") as f:
    json.dump(feature_names, f)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n[3/6] Train: {len(X_train)}, Test: {len(X_test)}")

print("\n[4/6] Training XGBoost model...")

scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)

model = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    eval_metric="logloss",
    random_state=42,
    verbosity=0
)

print("  Running 5-fold stratified CV...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1", n_jobs=-1)
print(f"  CV F1 scores: {cv_scores.round(3)}")
print(f"  Mean CV F1:   {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

model.fit(X_train, y_train)

print("\n[5/6] Evaluating on test set...")

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

f1_val = f1_score(y_test, y_pred)
prec   = precision_score(y_test, y_pred)
rec    = recall_score(y_test, y_pred)
auc    = roc_auc_score(y_test, y_prob)
acc    = (y_pred == y_test).mean()
fp_rate = ((y_pred == 1) & (y_test == 0)).sum() / max((y_test == 0).sum(), 1)

print(f"\n  Accuracy:        {acc:.4f}")
print(f"  F1-Score:        {f1_val:.4f}")
print(f"  Precision:       {prec:.4f}")
print(f"  Recall:          {rec:.4f}")
print(f"  ROC-AUC:         {auc:.4f}")
print(f"  False Pos Rate:  {fp_rate:.4f}")

print("\n  Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

print("  Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(f"  TN={cm[0,0]}  FP={cm[0,1]}")
print(f"  FN={cm[1,0]}  TP={cm[1,1]}")

importances = model.feature_importances_
feat_imp = sorted(zip(feature_names, importances), key=lambda x: -x[1])
print("\n  Top 10 Feature Importances:")
for name, imp in feat_imp[:10]:
    print(f"  {name:35s} {imp:.4f}")

print("\n[6/6] Building SHAP TreeExplainer...")

explainer = shap.TreeExplainer(model)
shap_values_train = explainer.shap_values(X_train)

global_shap = np.abs(shap_values_train).mean(axis=0)
shap_imp = sorted(zip(feature_names, global_shap), key=lambda x: -x[1])
print("  Top 10 Global SHAP Values:")
for name, sv in shap_imp[:10]:
    print(f"  {name:35s} {sv:.4f}")

print("\n  Saving model artifacts...")

with open(os.path.join(MODELS_DIR, "phishguard_model.pkl"), "wb") as f:
    pickle.dump(model, f)

with open(os.path.join(MODELS_DIR, "shap_explainer.pkl"), "wb") as f:
    pickle.dump(explainer, f)

training_report = {
    "accuracy":       round(float(acc), 4),
    "f1_score":       round(float(f1_val), 4),
    "precision":      round(float(prec), 4),
    "recall":         round(float(rec), 4),
    "roc_auc":        round(float(auc), 4),
    "false_pos_rate": round(float(fp_rate), 4),
    "cv_f1_mean":     round(float(cv_scores.mean()), 4),
    "cv_f1_std":      round(float(cv_scores.std()), 4),
    "n_train":        int(len(X_train)),
    "n_test":         int(len(X_test)),
    "n_features":     int(len(feature_names)),
    "model_type":     "XGBoostClassifier",
    "xai_method":     "SHAP TreeExplainer",
    "top_features":   [{"name": n, "importance": round(float(v), 4)} for n, v in feat_imp[:15]],
    "shap_global":    [{"name": n, "shap": round(float(v), 4)} for n, v in shap_imp[:15]],
    "confusion_matrix": cm.tolist(),
}

with open(os.path.join(MODELS_DIR, "training_report.json"), "w") as f:
    json.dump(training_report, f, indent=2)

print("\n" + "=" * 60)
print("Training complete!")
print(f"  Model saved:   models/phishguard_model.pkl")
print(f"  SHAP saved:    models/shap_explainer.pkl")
print(f"  Report saved:  models/training_report.json")
print("=" * 60)
