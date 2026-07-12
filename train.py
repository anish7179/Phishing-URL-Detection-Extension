"""
Phishing URL Detection — Production ML Training Pipeline
=========================================================
Trains on the FULL PhiUSIIL dataset (235,795 samples × 56 features)
using proper train/test splits, cross-validation, and model comparison.

Exports optimized weights for direct injection into background.js.
"""

import pandas as pd
import numpy as np
import re
import math
import json
import warnings
warnings.filterwarnings("ignore")

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler

# ═══════════════════════════════════════════════════════════════
# 1. LOAD FULL DATASET
# ═══════════════════════════════════════════════════════════════
print("=" * 60)
print("  PHISHING URL DETECTION — ML TRAINING PIPELINE")
print("=" * 60)

print("\n[1/6] Loading full PhiUSIIL dataset...")
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")
print(f"  ✓ Loaded {len(df):,} samples with {len(df.columns)} columns")
print(f"  ✓ Phishing: {(df['label'] == 1).sum():,} | Legitimate: {(df['label'] == 0).sum():,}")

# ═══════════════════════════════════════════════════════════════
# 2. FEATURE ENGINEERING
# ═══════════════════════════════════════════════════════════════
print("\n[2/6] Engineering features...")

# --- URL-derived features (computed from raw URL string) ---
suspicious_keywords = [
    "login", "verify", "update", "account", "secure", "authenticate",
    "banking", "password", "credential", "recover", "unlock", "wallet",
    "confirm", "support", "service", "billing", "invoice", "payment",
    "refund", "alert", "notice", "urgent", "required", "suspend",
    "limit", "restrict", "validation", "auth", "signin",
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "chase", "wellsfargo", "bankofamerica",
    "caixa", "acesso", "conta", "seguranca", "itau", "bradesco", "santander", "banco"
]

suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", 
                   ".click", ".link", ".hol.es", ".pe.hu"]

top_brands = [
    "apple", "google", "microsoft", "amazon", "facebook", "paypal", "netflix",
    "bankofamerica", "chase", "wellsfargo", "twitter", "instagram", "linkedin",
    "dropbox", "yahoo", "outlook", "caixa", "itau", "bradesco"
]

def shannon_entropy(s):
    if not s or len(s) == 0:
        return 0
    p = {}
    L = float(len(s))
    for c in s:
        p[c] = p.get(c, 0) + 1
    return -sum((count / L) * math.log2(count / L) for count in p.values())

def extract_url_features(url):
    url = str(url).lower()
    try:
        domain = url.split("//")[1].split("/")[0] if "//" in url else url.split("/")[0]
    except:
        domain = url
    path = url.split(domain, 1)[1] if domain in url else ""

    return {
        "f_hasKeywords": 1.0 if any(w in url for w in suspicious_keywords) else 0.0,
        "f_domainLen": min(len(domain) / 100.0, 1.0),
        "f_hyphens": min(domain.count("-") / 5.0, 1.0),
        "f_isIP": 1.0 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 0.0,
        "f_hasAt": 1.0 if "@" in url else 0.0,
        "f_hasEncoding": 1.0 if "%" in url else 0.0,
        "f_entropy": min(shannon_entropy(domain) / 5.0, 1.0),
        "f_spoofedBrand": 1.0 if any(
            b in domain and not domain.endswith(b + ".com") and not domain.endswith(b + ".org")
            for b in top_brands
        ) else 0.0,
        "f_suspiciousTLD": 1.0 if any(domain.endswith(t) for t in suspicious_tlds) else 0.0,
        "f_pathPlugin": 1.0 if ("/plugins/" in path or "/wp-" in path) else 0.0,
        "f_pathLogin": 1.0 if ("login" in path or "signin" in path or "account" in path) else 0.0,
        "f_deepPath": 1.0 if len([p for p in path.split("/") if p]) > 3 else 0.0,
        "f_urlLen": min(len(url) / 200.0, 1.0),
        "f_dots": min(url.count(".") / 8.0, 1.0),
        "f_subdomains": min(max(domain.count(".") - 1, 0) / 4.0, 1.0),
        "f_digits_ratio": sum(c.isdigit() for c in domain) / max(len(domain), 1),
    }

# Apply URL feature extraction
print("  Extracting URL-derived features...")
url_features_df = pd.DataFrame(df["URL"].apply(extract_url_features).tolist())
print(f"  ✓ Extracted {len(url_features_df.columns)} URL features")

# --- Dataset native features (pre-extracted in CSV) ---
native_feature_cols = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar",
    "ObfuscationRatio", "NoOfLettersInURL", "NoOfDegitsInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpijsInURL", "URLSimilarityIndex",
    "CharContinuationRate", "TLDLegitimateProb", "URLCharProb",
    "TLDLength", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "HasPasswordField", "HasSubmitButton", "HasHiddenFields",
    "HasExternalFormSubmit", "NoOfiFrame", "HasSocialNet",
    "HasCopyrightInfo", "NoOfImage", "NoOfCSS", "NoOfJS",
    "NoOfSelfRedirect", "NoOfPopup", "IsResponsive", "Robots",
    "HasFavicon", "HasDescription", "HasTitle",
    "DomainTitleMatchScore", "URLTitleMatchScore",
    "Bank", "Pay", "Crypto",
]

# Only keep columns that actually exist in the dataset
available_native = [c for c in native_feature_cols if c in df.columns]
print(f"  ✓ Found {len(available_native)} native dataset features")

# Combine all features
native_df = df[available_native].copy()
native_df = native_df.apply(pd.to_numeric, errors="coerce").fillna(0)

X = pd.concat([url_features_df, native_df], axis=1)

# Remove any duplicate columns
X = X.loc[:, ~X.columns.duplicated()]

y = df["label"].values
print(f"  ✓ Total feature matrix: {X.shape[0]:,} samples × {X.shape[1]} features")

# ═══════════════════════════════════════════════════════════════
# 3. TRAIN/TEST SPLIT
# ═══════════════════════════════════════════════════════════════
print("\n[3/6] Splitting into train/test sets (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  ✓ Train: {len(X_train):,} | Test: {len(X_test):,}")

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ═══════════════════════════════════════════════════════════════
# 4. TRAIN MULTIPLE MODELS & COMPARE
# ═══════════════════════════════════════════════════════════════
print("\n[4/6] Training models...")

models = {
    "Logistic Regression": LogisticRegression(max_iter=2000, C=1.0, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1),
    "Gradient Boosting": GradientBoostingClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, random_state=42),
}

results = {}
best_model_name = None
best_accuracy = 0

for name, model in models.items():
    print(f"\n  Training {name}...")
    if name == "Logistic Regression":
        model.fit(X_train_scaled, y_train)
        y_pred = model.predict(X_test_scaled)
    else:
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    results[name] = {"accuracy": acc, "model": model, "predictions": y_pred}
    
    print(f"  ✓ {name}: {acc * 100:.2f}% accuracy")
    
    # Cross validation
    if name == "Logistic Regression":
        cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="accuracy")
    else:
        cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="accuracy")
    print(f"    Cross-validation: {cv_scores.mean() * 100:.2f}% ± {cv_scores.std() * 100:.2f}%")

    if acc > best_accuracy:
        best_accuracy = acc
        best_model_name = name

print(f"\n  ★ Best Model: {best_model_name} ({best_accuracy * 100:.2f}%)")

# ═══════════════════════════════════════════════════════════════
# 5. DETAILED EVALUATION OF BEST MODEL
# ═══════════════════════════════════════════════════════════════
print(f"\n[5/6] Detailed evaluation of {best_model_name}...")
best_preds = results[best_model_name]["predictions"]
print(classification_report(y_test, best_preds, target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, best_preds)
print(f"  Confusion Matrix:")
print(f"    True Negatives:  {cm[0][0]:,}  |  False Positives: {cm[0][1]:,}")
print(f"    False Negatives: {cm[1][0]:,}  |  True Positives:  {cm[1][1]:,}")

# ═══════════════════════════════════════════════════════════════
# 6. EXPORT FOR JAVASCRIPT INTEGRATION
# ═══════════════════════════════════════════════════════════════
print(f"\n[6/6] Exporting model for JavaScript integration...")

# For the Chrome extension, we use the Logistic Regression model
# because it can be represented as simple weights in JS
lr_model = results["Logistic Regression"]["model"]

feature_names = list(X.columns)
weights = lr_model.coef_[0]
bias = lr_model.intercept_[0]

# Separate URL-derived features (computable in JS) from native features (need DOM scraping)
url_feature_names = list(url_features_df.columns)
native_feature_names = [c for c in feature_names if c not in url_feature_names]

# Get scaler params for the features
means = scaler.mean_
stds = scaler.scale_

# Build the export object
export = {
    "bias": float(bias),
    "features": [],
    "scaler": {"means": means.tolist(), "scales": stds.tolist()},
    "accuracy": float(results["Logistic Regression"]["accuracy"]),
    "best_model": best_model_name,
    "best_accuracy": float(best_accuracy),
}

for i, fname in enumerate(feature_names):
    export["features"].append({
        "name": fname,
        "weight": float(weights[i]),
        "mean": float(means[i]),
        "scale": float(stds[i]),
        "source": "url" if fname in url_feature_names else "dataset_native",
    })

with open("ml_model_export.json", "w") as f:
    json.dump(export, f, indent=2)

# Also generate the JS weight snippet for URL-only features
print("\n  URL-extractable feature weights for background.js:")
print(f"  const W_bias = {bias:.6f};")
print(f"  const W_means = [{', '.join(f'{m:.6f}' for m in means)}];")
print(f"  const W_scales = [{', '.join(f'{s:.6f}' for s in stds)}];")

print(f"\n{'=' * 60}")
print(f"  TRAINING COMPLETE")
print(f"  Logistic Regression: {results['Logistic Regression']['accuracy'] * 100:.2f}%")
if best_model_name != "Logistic Regression":
    print(f"  {best_model_name}: {best_accuracy * 100:.2f}%")
print(f"  Exported to: ml_model_export.json")
print(f"{'=' * 60}")
