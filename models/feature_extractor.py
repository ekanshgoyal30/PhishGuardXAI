"""
PhishGuard Feature Extractor
-----------------------------
Extracts 40+ features from email text for ML classification.

Feature groups:
  1. Lexical / bag-of-words (TF-IDF)
  2. Urgency & threat language (lexicon)
  3. URL & domain features
  4. Structural features (email metadata)
  5. Social engineering tactics
  6. PII / payload signals
"""

import re
import math
from urllib.parse import urlparse
import numpy as np

# ── LEXICONS ────────────────────────────────────────────────────────────────────

URGENCY_WORDS = {
    "urgent", "immediately", "asap", "right now", "expires", "expiring",
    "suspended", "warning", "final", "act now", "limited time",
    "24 hours", "48 hours", "72 hours", "today", "deadline", "hurry",
    "don't delay", "do not delay", "time sensitive", "respond now",
    "last chance", "expire", "critical"
}

THREAT_WORDS = {
    "suspended", "terminated", "locked", "closed", "blocked", "deactivated",
    "deleted", "banned", "disabled", "penalized", "arrested", "prosecuted",
    "legal action", "lawsuit", "wage garnishment", "forfeit", "void"
}

PII_WORDS = {
    "password", "social security", "ssn", "credit card", "bank account",
    "account number", "routing number", "date of birth", "mother maiden",
    "pin number", "cvv", "expiration date", "billing address",
    "credit card number", "debit card", "bank details"
}

AUTHORITY_WORDS = {
    "irs", "fbi", "bank of america", "paypal", "amazon", "microsoft",
    "google", "apple", "facebook", "linkedin", "netflix", "ceo", "director",
    "it department", "it support", "help desk", "security team", "legal",
    "government", "federal", "official"
}

SECRECY_WORDS = {
    "confidential", "don't tell", "do not tell", "keep secret", "between us",
    "do not discuss", "private", "nobody else", "do not share",
    "surprise", "just between"
}

FINANCIAL_WORDS = {
    "wire transfer", "wiring", "bank transfer", "routing number",
    "swift", "iban", "gift card", "gift cards", "bitcoin",
    "cryptocurrency", "western union", "money gram", "send money",
    "processing fee", "advance fee", "claim your prize"
}

MACRO_WORDS = {
    "enable macros", "enable editing", "enable content",
    ".xlsm", ".docm", ".xlsb", ".pptm", "macro"
}

SAFE_SIGNALS = {
    "unsubscribe", "privacy policy", "terms of service",
    "manage preferences", "opt out", "you received this",
    "this is an automated", "do not reply"
}

# ── SUSPICIOUS TLD / PATTERNS ───────────────────────────────────────────────────
SUSPICIOUS_TLDS = {".xyz", ".ru", ".win", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq", ".info", ".co"}
SUSPICIOUS_PATTERNS = [
    r"secure[-_]?login", r"account[-_]?verify", r"reset[-_]?password",
    r"helpdesk\.", r"support[-_]?center", r"verify[-_]?account",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP address URL
    r"[a-zA-Z]+-[a-zA-Z]+-[a-zA-Z]+\.",       # multi-hyphen domain
]

LEGIT_DOMAINS = {
    "gmail.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "slack.com", "notion.so", "zoom.us", "linkedin.com",
    "atlassian.net", "spotify.com", "coursera.org", "stackoverflow.com",
    "paypal.com", "bankofamerica.com", "hdfcbank.com", "indigoair.in",
    "facebook.com", "twitter.com", "netflix.com"
}

# ── FEATURE EXTRACTION ──────────────────────────────────────────────────────────

def extract_urls(text):
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text, re.IGNORECASE)

def url_entropy(url):
    """Shannon entropy of URL characters — high entropy = suspicious."""
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    total = len(url)
    return -sum((f/total) * math.log2(f/total) for f in freq.values())

def analyze_url(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        features = {
            "url_length": len(url),
            "domain_length": len(domain),
            "has_ip": 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0,
            "has_https": 1 if url.startswith("https://") else 0,
            "suspicious_tld": 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0,
            "hyphen_count": domain.count("-"),
            "subdomain_count": len(domain.split(".")) - 2,
            "suspicious_pattern": 1 if any(re.search(p, full) for p in SUSPICIOUS_PATTERNS) else 0,
            "path_depth": len([p for p in path.split("/") if p]),
            "url_entropy": url_entropy(url),
            "is_legit_domain": 1 if any(domain.endswith(d) for d in LEGIT_DOMAINS) else 0,
        }
        return features
    except Exception:
        return {k: 0 for k in ["url_length","domain_length","has_ip","has_https",
                                "suspicious_tld","hyphen_count","subdomain_count",
                                "suspicious_pattern","path_depth","url_entropy","is_legit_domain"]}

def count_lexicon(text_lower, lexicon):
    return sum(1 for w in lexicon if w in text_lower)

def extract_features(subject: str, sender: str, body: str) -> dict:
    """
    Extract 40+ numerical features from an email.
    Returns a flat dict suitable for ML models.
    """
    combined = f"{subject} {sender} {body}".lower()
    body_lower = body.lower()
    subject_lower = subject.lower()

    # 1. Lexicon-based signals
    urgency_count     = count_lexicon(combined, URGENCY_WORDS)
    threat_count      = count_lexicon(combined, THREAT_WORDS)
    pii_count         = count_lexicon(combined, PII_WORDS)
    authority_count   = count_lexicon(combined, AUTHORITY_WORDS)
    secrecy_count     = count_lexicon(combined, SECRECY_WORDS)
    financial_count   = count_lexicon(combined, FINANCIAL_WORDS)
    macro_count       = count_lexicon(combined, MACRO_WORDS)
    safe_count        = count_lexicon(combined, SAFE_SIGNALS)

    # 2. URL features (aggregate over all URLs in email)
    urls = extract_urls(body)
    if urls:
        url_feats_list = [analyze_url(u) for u in urls]
        url_feat_keys = url_feats_list[0].keys()
        url_feats = {k: max(f[k] for f in url_feats_list) for k in url_feat_keys}
        url_feats["url_count"] = len(urls)
    else:
        url_feats = {
            "url_length": 0, "domain_length": 0, "has_ip": 0, "has_https": 0,
            "suspicious_tld": 0, "hyphen_count": 0, "subdomain_count": 0,
            "suspicious_pattern": 0, "path_depth": 0, "url_entropy": 0.0,
            "is_legit_domain": 0, "url_count": 0
        }

    # 3. Sender features
    sender_lower = sender.lower()
    sender_domain = sender.split("@")[-1] if "@" in sender else sender
    sender_is_legit = 1 if any(sender_domain.endswith(d) for d in LEGIT_DOMAINS) else 0
    sender_has_hyphen = 1 if "-" in sender_domain else 0
    sender_tld_suspicious = 1 if any(sender_domain.endswith(t.lstrip(".")) for t in SUSPICIOUS_TLDS) else 0

    # Display name mismatch: sender claims to be someone but domain differs
    impersonates_brand = 0
    for brand in ["paypal", "amazon", "microsoft", "google", "apple", "bank", "irs", "facebook"]:
        if brand in sender_lower and not any(f"{brand}.com" in sender_lower or f"{brand}.org" in sender_lower for _ in [1]):
            if brand not in sender_domain:
                impersonates_brand = 1
                break

    # 4. Structural / text features
    body_length = len(body)
    subject_length = len(subject)
    exclamation_count = body.count("!")
    caps_ratio = sum(1 for c in body if c.isupper()) / max(len(body), 1)
    word_count = len(body.split())
    has_attachment_ext = 1 if re.search(r'\.(xlsm|docm|exe|zip|rar|xlsb|pptm|bat|vbs)', body_lower) else 0
    dollar_amount = 1 if re.search(r'\$[\d,]+', body) else 0
    time_pressure = 1 if re.search(r'\d+\s*(hour|hours|day|days|minute|minutes)', body_lower) else 0
    question_count = body.count("?")

    # 5. Subject signals
    subject_urgent = 1 if any(w in subject_lower for w in ["urgent", "action required", "warning", "suspended", "final"]) else 0
    subject_caps = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)

    # 6. Composite derived features
    social_eng_score = (urgency_count * 2 + threat_count * 2 + secrecy_count * 3 +
                        financial_count * 2 + impersonates_brand * 3) / 10.0
    credential_risk  = (pii_count * 3 + url_feats["suspicious_pattern"] * 2 +
                        url_feats["has_ip"] * 3 + macro_count * 4) / 10.0

    features = {
        # Lexicon
        "urgency_count":      urgency_count,
        "threat_count":       threat_count,
        "pii_count":          pii_count,
        "authority_count":    authority_count,
        "secrecy_count":      secrecy_count,
        "financial_count":    financial_count,
        "macro_count":        macro_count,
        "safe_signal_count":  safe_count,

        # URL
        **{f"url_{k}": v for k, v in url_feats.items()},

        # Sender
        "sender_is_legit":          sender_is_legit,
        "sender_has_hyphen":        sender_has_hyphen,
        "sender_tld_suspicious":    sender_tld_suspicious,
        "impersonates_brand":       impersonates_brand,

        # Structure
        "body_length":           body_length,
        "subject_length":        subject_length,
        "exclamation_count":     exclamation_count,
        "caps_ratio":            round(caps_ratio, 4),
        "word_count":            word_count,
        "has_attachment_ext":    has_attachment_ext,
        "dollar_amount":         dollar_amount,
        "time_pressure":         time_pressure,
        "question_count":        question_count,
        "subject_urgent":        subject_urgent,
        "subject_caps_ratio":    round(subject_caps, 4),

        # Composite
        "social_eng_score":      round(social_eng_score, 4),
        "credential_risk":       round(credential_risk, 4),
    }

    return features


def get_feature_names():
    """Return ordered list of all feature names (for SHAP alignment)."""
    dummy = extract_features("test", "test@test.com", "test body")
    return list(dummy.keys())


if __name__ == "__main__":
    # Quick test
    test = extract_features(
        subject="URGENT: Your account has been suspended",
        sender="security@bankofamerica-verify.net",
        body="Your account has been SUSPENDED. Verify IMMEDIATELY or it will be permanently terminated. Click: http://bankofamerica-secure-login.xyz/verify. Provide your SSN and password."
    )
    print("Features extracted:", len(test))
    for k, v in test.items():
        if v != 0:
            print(f"  {k}: {v}")
