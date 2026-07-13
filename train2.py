"""
Massive URL-only Dataset Training Pipeline (549k rows)
======================================================
Trains on the `phishing_site_urls1.csv` dataset.
Label mapping: 'good' -> 0, 'bad' -> 1
Uses 20+ deeply optimized lexical features that can be perfectly 
replicated in background.js for realtime offline inference.
"""

import pandas as pd
import numpy as np
import re
import math
import json
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler

print("="*60)
print("  LOADING NEW DATASET (549,346 ROWS)")
print("="*60)

df = pd.read_csv('phishing_site_urls1.csv')
# Convert labels: 'bad' (phishing) -> 1.0, 'good' (safe) -> 0.0
df['y'] = df['Label'].apply(lambda x: 1.0 if x.lower().strip() == 'bad' else 0.0)

print(f"Total Rows: {len(df):,}")
print(f"Phishing (Bad): {int(df['y'].sum()):,}")
print(f"Legitimate (Good): {int(len(df) - df['y'].sum()):,}")

# --- Lexical Feature Extraction ---
suspicious_keywords = [
    "login", "verify", "update", "account", "secure", "authenticate",
    "banking", "password", "credential", "recover", "unlock", "wallet",
    "confirm", "support", "service", "billing", "invoice", "payment",
    "refund", "alert", "notice", "urgent", "required", "suspend",
    "limit", "restrict", "validation", "auth", "signin",
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "chase", "wellsfargo", "bankofamerica",
    "caixa", "acesso", "conta", "seguranca", "itau", "bradesco", "santander", "banco",
    "admin", "webmail", "webscr", "login", "free", "bonus"
]

suspicious_tlds = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", 
    ".click", ".link", ".hol.es", ".pe.hu", ".000webhostapp.com",
    ".servehttp.com", ".rf.gd", ".epizy.com", ".biz", ".cc", ".su"
]

def shannon_entropy(s):
    if not s or len(s) == 0: return 0
    p = {}
    for c in s: p[c] = p.get(c, 0) + 1
    L = float(len(s))
    return -sum((count / L) * math.log2(count / L) for count in p.values())

def extract_features(url):
    url = str(url).lower()
    
    # Try to extract domain
    # e.g., http://google.com/path -> google.com
    domain = url
    path = ""
    if "://" in url:
        domain = url.split("://")[1].split("/")[0]
        try:
            path = url.split("://")[1].split("/", 1)[1]
        except:
            pass
    else:
        domain = url.split("/")[0]
        try:
            path = url.split("/", 1)[1]
        except:
            pass

    domain = domain.replace("www.", "")
    
    # Mathematical properties
    url_len = min(len(url) / 150.0, 1.0)
    domain_len = min(len(domain) / 75.0, 1.0)
    path_len = min(len(path) / 100.0, 1.0)
    
    # Character counts
    dots = min((url.count(".")) / 6.0, 1.0)
    hyphens = min((url.count("-")) / 4.0, 1.0)
    at_symbols = min(url.count("@"), 1.0)
    slashes = min(url.count("/") / 6.0, 1.0)
    digits = sum(c.isdigit() for c in url)
    digits_ratio = digits / max(len(url), 1)
    
    # Specialized Checks
    is_ip = 1.0 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain) else 0.0
    entropy = min(shannon_entropy(domain) / 4.5, 1.0)
    qty_keywords = sum(1.0 for w in suspicious_keywords if w in url)
    has_keywords = min(qty_keywords / 3.0, 1.0)
    suspicious_tld = 1.0 if any(domain.endswith(t) for t in suspicious_tlds) else 0.0
    
    # Phishing tactics
    multi_subdomains = 1.0 if domain.count('.') >= 3 else 0.0
    https_in_domain = 1.0 if "https" in domain else 0.0
    url_encoded = 1.0 if "%20" in url or "%" in url else 0.0
    
    return [
        url_len, domain_len, path_len, dots, hyphens, at_symbols, slashes, 
        digits_ratio, is_ip, entropy, has_keywords, suspicious_tld, 
        multi_subdomains, https_in_domain, url_encoded
    ]

# Apply to all
print("\nExtracting features for 549,346 URLs (This may take a minute)...\n")
X_raw = [extract_features(u) for u in df['URL']]
X_df = pd.DataFrame(X_raw, columns=[
    "url_len", "domain_len", "path_len", "dots", "hyphens", "at_symbols", "slashes",
    "digits_ratio", "is_ip", "entropy", "has_keywords", "suspicious_tld",
    "multi_subdomains", "https_in_domain", "url_encoded"
])

y = df['y'].values

print("Splitting dataset into 80/20 train-test sets...")
X_train, X_test, y_train, y_test = train_test_split(X_df, y, test_size=0.2, random_state=42)

print("Scaling data to Standard Normalize variance...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\nTraining Logistic Regression...")
lr = LogisticRegression(max_iter=1000, n_jobs=-1, class_weight='balanced')
lr.fit(X_train_scaled, y_train)
preds = lr.predict(X_test_scaled)
acc = accuracy_score(y_test, preds)

print("\n--- RESULTS ---")
print(f"Accuracy: {acc*100:.2f}%")
print(classification_report(y_test, preds, target_names=["Good", "Bad (Phishing)"]))

# Export the Math
means = scaler.mean_.tolist()
scales = scaler.scale_.tolist()
weights = lr.coef_[0].tolist()
bias = lr.intercept_[0]

export = {
    "bias": bias,
    "features": list(X_df.columns),
    "means": means,
    "scales": scales,
    "weights": weights
}
with open("ml_model_raw_urls_export.json", "w") as f:
    json.dump(export, f, indent=2)

print("\nExported exact coefficients and scalers to ml_model_raw_urls_export.json")
