import pandas as pd
import numpy as np
import re
import math
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

print("Loading dataset...")
df = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv', skipinitialspace=True)

# Some datasets label '1' for phishing and '0' for safe, or vice-versa.
# Let's assume label==1 is phishing, and label==0 is legitimate if it's binary.
print(f"Dataset shape: {df.shape}")

suspicious_keywords = [
  "login", "verify", "update", "account", "secure", "authenticate",
  "banking", "password", "credential", "recover", "unlock", "wallet",
  "confirm", "support", "service", "billing", "invoice", "payment",
  "refund", "alert", "notice", "urgent", "required", "suspend",
  "limit", "restrict", "validation", "auth", "signin",
  "paypal", "apple", "microsoft", "google", "amazon", "facebook",
  "chase", "wellsfargo", "bankofamerica"
]

suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".click", ".link"]

def shannon_entropy(s):
    if not s: return 0
    p, lns = {}, float(len(s))
    for c in s: p[c] = p.get(c, 0) + 1
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def extract_features(row):
    url = str(row.get('URL', '')).lower()
    
    # Very basic domain extraction since we are doing this fast
    domain = url.split('/')[2] if '//' in url else url.split('/')[0]
    path = url.split(domain)[1] if domain in url and len(url.split(domain))>1 else ""
    
    f_suspiciousWords = 1.0 if any(w in url for w in suspicious_keywords) else 0.0
    f_domainLen = min(len(domain) / 100.0, 1.0)
    f_hyphens = min(domain.count('-') / 5.0, 1.0)
    f_ipAddress = 1.0 if re.match(r'.*\d+\.\d+\.\d+\.\d+.*', domain) else 0.0
    f_atSymbols = 1.0 if '@' in url else 0.0
    f_encoding = 1.0 if '%' in url else 0.0
    f_entropy = min(shannon_entropy(domain) / 5.0, 1.0)
    
    # We spoof brand offline just via keyword matching for training
    topBrands = ["apple", "google", "microsoft", "amazon", "facebook", "paypal", "netflix", "bankofamerica", "chase", "wellsfargo", "twitter"]
    f_spoofedBrand = 1.0 if any(b in domain for b in topBrands) and not any(domain.endswith(b+".com") for b in topBrands) else 0.0
    f_homoglyphs = 1.0 if re.match(r'.*[^\x00-\x7F]+.*', domain) else 0.0
    f_suspiciousTLD = 1.0 if any(domain.endswith(t) for t in suspiciousTLDs) else 0.0
    
    f_suspiciousAge = 0.0 # Age requires network lookup, defaulting 0
    
    f_pathPlugin = 1.0 if len(path) > 12 and ('/plugins/' in path or '/wp-' in path) else 0.0
    f_pathLogin = 1.0 if 'login' in path or 'chase' in path else 0.0
    f_deepPath = 1.0 if len(path.split('/')) > 3 else 0.0

    return [
        f_suspiciousWords, f_domainLen, f_hyphens, f_ipAddress,
        f_atSymbols, f_encoding, f_entropy, f_spoofedBrand,
        f_homoglyphs, f_suspiciousTLD, f_suspiciousAge,
        f_pathPlugin, f_pathLogin, f_deepPath
    ]

print("Extracting features (This might take a minute...)")
# Process 25k records heavily stratified to save computing time if 235k is too slow,
# We will do 50k samples
df_sample = df.sample(n=min(50000, len(df)), random_state=42)

X = df_sample.apply(extract_features, axis=1).tolist()
y = df_sample['label'].tolist()

print("Training Logistic Regression Model...")
clf = LogisticRegression(random_state=42, max_iter=1000)
clf.fit(X, y)

print("Accuracy:", clf.score(X, y))
print("INTERCEPT:", clf.intercept_[0])
class_mapping = 1.0 if clf.classes_[1] == 1 else -1.0 # Ensure positive weights target phishing
weights = [w * class_mapping for w in clf.coef_[0]]

print("WEIGHTS:", weights)

# Let's save a config to inject
out = f"const W_bias = {clf.intercept_[0] * class_mapping:.4f};\nconst W = [\n"
features = ["f_suspiciousWords", "f_domainLen", "f_hyphens", "f_ipAddress", "f_atSymbols", "f_encoding", "f_entropy", "f_spoofedBrand", "f_homoglyphs", "f_suspiciousTLD", "f_suspiciousAge", "f_pathPlugin", "f_pathLogin", "f_deepPath"]

for f, w in zip(features, weights):
    out += f"  {f} * {w:.4f},\n"
    
out += "];"

with open("ml_weights.txt", "w") as f2:
    f2.write(out)

print("Export complete.")
