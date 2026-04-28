"""
PhishGuard XAI - FastAPI Backend
Run: py -m uvicorn api.main:app --reload --port 8000
"""

import sys, os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import json
import pickle
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import shap

from models.feature_extractor import extract_features

MODELS_DIR = os.path.join(BASE_DIR, "models")

print("Loading PhishGuard model...")
try:
    with open(os.path.join(MODELS_DIR, "phishguard_model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "shap_explainer.pkl"), "rb") as f:
        explainer = pickle.load(f)
    with open(os.path.join(MODELS_DIR, "feature_names.json")) as f:
        feature_names = json.load(f)
    with open(os.path.join(MODELS_DIR, "training_report.json")) as f:
        training_report = json.load(f)
    print(f"Model loaded. F1={training_report['f1_score']}, AUC={training_report['roc_auc']}")
except FileNotFoundError as e:
    print(f"Model not found: {e}")
    print("Run: py train.py first")
    model = None
    explainer = None
    feature_names = []
    training_report = {}

def classify_attack_type(features: dict, body: str, score: float) -> list:
    body_lower = body.lower()
    tags = []
    if features.get("macro_count", 0) > 0:
        tags.append({"label": "Malware Delivery", "severity": "critical"})
    if features.get("financial_count", 0) > 0 and features.get("secrecy_count", 0) > 0:
        tags.append({"label": "BEC / CEO Fraud", "severity": "critical"})
    if features.get("pii_count", 0) > 0 and features.get("url_suspicious_pattern", 0) > 0:
        tags.append({"label": "Credential Harvesting", "severity": "critical"})
    if features.get("authority_count", 0) > 0 and features.get("impersonates_brand", 0) > 0:
        tags.append({"label": "Brand Impersonation", "severity": "high"})
    if features.get("urgency_count", 0) >= 2:
        tags.append({"label": "Urgency Manipulation", "severity": "high"})
    if features.get("secrecy_count", 0) > 0:
        tags.append({"label": "Isolation Tactic", "severity": "medium"})
    if features.get("financial_count", 0) > 0 and "prize" in body_lower:
        tags.append({"label": "Advance Fee Fraud", "severity": "high"})
    if features.get("url_suspicious_tld", 0) > 0:
        tags.append({"label": "Domain Spoofing", "severity": "high"})
    if score < 0.3:
        tags.append({"label": "Appears Legitimate", "severity": "safe"})
    return tags

def generate_recommendations(features: dict, score: float, tags: list) -> list:
    recos = []
    tag_labels = [t["label"] for t in tags]
    if score > 0.7:
        recos.append({"icon": "🚫", "text": "Block and quarantine this message immediately.", "priority": "critical"})
    if score > 0.5:
        recos.append({"icon": "🔍", "text": "Escalate to SOC team for investigation.", "priority": "high"})
    if features.get("pii_count", 0) > 0:
        recos.append({"icon": "🔐", "text": "Do NOT enter credentials or PII on any linked pages.", "priority": "critical"})
    if "BEC" in str(tag_labels) or features.get("financial_count", 0) > 0:
        recos.append({"icon": "📞", "text": "Verify financial requests via phone — never email alone.", "priority": "critical"})
    if features.get("macro_count", 0) > 0:
        recos.append({"icon": "⚙️", "text": "Never enable macros from unknown senders.", "priority": "critical"})
    if features.get("url_suspicious_pattern", 0) > 0:
        recos.append({"icon": "🔗", "text": "Report suspicious domain to PhishTank.", "priority": "high"})
    if score < 0.3:
        recos.append({"icon": "✅", "text": "Email appears legitimate — no action required.", "priority": "info"})
    if not recos:
        recos.append({"icon": "👁️", "text": "Exercise caution and verify with sender directly.", "priority": "medium"})
    return recos

def highlight_text(body: str, features: dict) -> list:
    import re
    from models.feature_extractor import (URGENCY_WORDS, THREAT_WORDS, PII_WORDS,
                                           SECRECY_WORDS, FINANCIAL_WORDS, MACRO_WORDS)
    body_lower = body.lower()
    lexicons = [
        (URGENCY_WORDS,  "urgency", "Urgency/pressure language"),
        (THREAT_WORDS,   "threat",  "Threat/fear language"),
        (PII_WORDS,      "danger",  "PII or credential request"),
        (SECRECY_WORDS,  "danger",  "Secrecy/isolation tactic"),
        (FINANCIAL_WORDS,"danger",  "Financial fraud signal"),
        (MACRO_WORDS,    "danger",  "Malware/macro signal"),
    ]
    found = {}
    for lexicon, severity, reason in lexicons:
        for word in lexicon:
            idx = body_lower.find(word)
            if idx != -1:
                span = body[idx:idx+len(word)]
                if span not in found:
                    found[span] = {"severity": severity, "reason": reason, "index": idx}
    for m in re.finditer(r'https?://\S+', body):
        found[m.group()] = {"severity": "danger", "reason": "URL - verify domain", "index": m.start()}
    highlights = [{"text": t, **v} for t, v in found.items()]
    highlights.sort(key=lambda x: x["index"])
    return highlights

class AnalyzeRequest(BaseModel):
    body: str
    subject: Optional[str] = ""
    sender: Optional[str] = ""
    channel: Optional[str] = "email"

app = FastAPI(
    title="PhishGuard XAI API",
    description="Real-time phishing detection with SHAP explainability",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "f1_score": training_report.get("f1_score"),
    }

@app.get("/model-info")
def model_info():
    return training_report

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    if model is None:
        raise HTTPException(503, "Model not loaded. Run py train.py first.")

    feats = extract_features(req.subject, req.sender, req.body)
    feat_df = pd.DataFrame([feats])

    for fn in feature_names:
        if fn not in feat_df.columns:
            feat_df[fn] = 0
    feat_df = feat_df[feature_names]

    prob = float(model.predict_proba(feat_df)[0][1])
    score_pct = int(round(prob * 100))

    if prob >= 0.70:
        verdict, verdict_class = "PHISHING", "danger"
    elif prob >= 0.40:
        verdict, verdict_class = "SUSPICIOUS", "warn"
    else:
        verdict, verdict_class = "SAFE", "safe"

    confidence = max(prob, 1 - prob)

    sv = explainer.shap_values(feat_df)[0]
    shap_pairs = sorted(zip(feature_names, sv), key=lambda x: abs(x[1]), reverse=True)[:12]
    max_shap = max(abs(v) for _, v in shap_pairs) if shap_pairs else 1.0

    shap_out = []
    for fname, fval in shap_pairs:
        shap_out.append({
            "feature":       fname.replace("_", " ").title(),
            "raw_feature":   fname,
            "value":         round(float(fval), 4),
            "direction":     "increases_risk" if fval > 0 else "reduces_risk",
            "magnitude":     round(abs(fval) / max(max_shap, 1e-8), 4),
            "feature_value": float(feats.get(fname, 0))
        })

    fi = sorted(zip(feature_names, model.feature_importances_), key=lambda x: -x[1])[:10]
    feat_imp_out = [{"feature": n.replace("_", " ").title(), "importance": round(float(v), 4)} for n, v in fi]

    urgency_s   = min(int(feats.get("urgency_count",0)*20 + feats.get("threat_count",0)*15), 100)
    deception_s = min(int(feats.get("url_suspicious_pattern",0)*30 + feats.get("pii_count",0)*20 + feats.get("macro_count",0)*30 + feats.get("impersonates_brand",0)*25), 100)
    authority_s = min(int(feats.get("authority_count",0)*15 + feats.get("impersonates_brand",0)*30 + feats.get("financial_count",0)*15), 100)
    payload_s   = min(int(feats.get("pii_count",0)*25 + feats.get("financial_count",0)*20 + feats.get("macro_count",0)*40 + feats.get("has_attachment_ext",0)*30), 100)

    attack_types = classify_attack_type(feats, req.body, prob)
    highlights   = highlight_text(req.body, feats)
    recos        = generate_recommendations(feats, prob, attack_types)

    return {
        "threat_score":        round(prob, 4),
        "threat_score_pct":    score_pct,
        "verdict":             verdict,
        "verdict_class":       verdict_class,
        "confidence":          round(confidence, 4),
        "attack_types":        attack_types,
        "urgency_score":       urgency_s,
        "deception_score":     deception_s,
        "authority_score":     authority_s,
        "payload_score":       payload_s,
        "shap_values":         shap_out,
        "feature_importances": feat_imp_out,
        "highlighted_spans":   highlights,
        "recommendations":     recos,
        "model_version":       "phishguard-xgb-v1.0",
        "feature_count":       len(feature_names),
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
