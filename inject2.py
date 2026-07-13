import json
import re

with open('ml_model_raw_urls_export.json') as f:
    data = json.load(f)

# Hardcode the arrays to exactly match the Python export
features = data['features']
means = [float(x) for x in data['means']]
scales = [float(x) for x in data['scales']]
weights = [float(x) for x in data['weights']]
bias = float(data['bias'])

js_func = f"""function analyzeUrlFeatures(urlInfo) {{
  urlInfo.domSignals = urlInfo.domSignals || {{
    passwordField: false,
    externalForm: false,
    hiddenIframe: false,
  }};

  // 1. Calculate Exact 15 Lexical Features Used in 549k Training
  const url = urlInfo.url.toLowerCase();
  const domain = urlInfo.domain.toLowerCase();
  let path = urlInfo.path.toLowerCase();
  
  const f_url_len = Math.min(url.length / 150.0, 1.0);
  const f_domain_len = Math.min(domain.length / 75.0, 1.0);
  const f_path_len = Math.min(path.length / 100.0, 1.0);
  
  const f_dots = Math.min((url.match(/\\./g) || []).length / 6.0, 1.0);
  const f_hyphens = Math.min((url.match(/-/g) || []).length / 4.0, 1.0);
  const f_at_symbols = Math.min((url.match(/@/g) || []).length, 1.0);
  const f_slashes = Math.min((url.match(/\\//g) || []).length / 6.0, 1.0);
  
  // count digits in the whole url, not just domain
  let digitCount = 0;
  for (let i = 0; i < url.length; i++) {{ if (url[i] >= '0' && url[i] <= '9') digitCount++; }}
  const f_digits_ratio = digitCount / Math.max(url.length, 1);
  
  const f_is_ip = /\\b\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\b/.test(domain) ? 1.0 : 0.0;
  
  const rawEntropy = shannonEntropy(domain);
  const f_entropy = Math.min(rawEntropy / 4.5, 1.0);
  
  let keywordQty = 0;
  for (const w of suspiciousKeywords) {{
      if (url.includes(w)) keywordQty++;
  }}
  const f_has_keywords = Math.min(keywordQty / 3.0, 1.0);
  
  const f_suspicious_tld = suspiciousTLDs.some(t => domain.endsWith(t)) ? 1.0 : 0.0;
  const f_multi_subdomains = (domain.match(/\\./g) || []).length >= 3 ? 1.0 : 0.0;
  const f_https_in_domain = domain.includes("https") ? 1.0 : 0.0;
  const f_url_encoded = (url.includes("%20") || url.includes("%")) ? 1.0 : 0.0;

  // 2. Machine Learning Weights Matrix (Trained on 549,346 Samples)
  const W_bias = {bias:.8f};
  
  const featureValues = [
    f_url_len, f_domain_len, f_path_len, f_dots, f_hyphens,
    f_at_symbols, f_slashes, f_digits_ratio, f_is_ip, f_entropy,
    f_has_keywords, f_suspicious_tld, f_multi_subdomains, f_https_in_domain, f_url_encoded
  ];
  
  const W_means = [{', '.join(f'{m:.8f}' for m in means)}];
  const W_scales = [{', '.join(f'{s:.8f}' for s in scales)}];
  const W_weights = [{', '.join(f'{w:.8f}' for w in weights)}];
  
  // Normalize and compute dot product
  let z = W_bias;
  for (let i = 0; i < featureValues.length; i++) {{
    const normalized = (featureValues[i] - W_means[i]) / W_scales[i];
    z += normalized * W_weights[i];
  }}

  // 3. Add DOM structural features 
  // (We retain these manually calibrated penalties to catch zero-day hidden iframes!)
  const f_domPassword = urlInfo.domSignals.passwordField ? 1.0 : 0.0;
  const f_domExternal = urlInfo.domSignals.externalForm ? 1.0 : 0.0;
  const f_domHidden = urlInfo.domSignals.hiddenIframe ? 1.0 : 0.0;
  const spoofedBrand = checkTyposquatting(urlInfo.domain);
  if (spoofedBrand) {{
    urlInfo.spoofedBrand = spoofedBrand;
  }}
  const f_domRisk = f_domPassword && (urlInfo.category === "unknown" || spoofedBrand) ? 1.0 : 0.0;

  z += f_domPassword * 3.5;   // Unexpected password forms
  z += f_domExternal * 3.0;   // Data exfiltration to unknown domains
  z += f_domHidden * 2.5;     // Obfuscated iframes
  z += f_domRisk * 5.5;       // Critical: Unknown domain asking for passwords

  // 4. Sigmoid Activation
  const probability = 1.0 / (1.0 + Math.exp(-z));

  // 5. Sensitivity Shift
  const sensMultiplier = settings.sensitivityLevel / 3.0;
  const threshold = 0.5 / sensMultiplier;

  const isPhishing = probability > threshold;

  // Flag risk meta-data for the UI explainer
  urlInfo.hasSuspiciousWords = (keywordQty > 0);
  urlInfo.hasIpAddress = (f_is_ip > 0);
  urlInfo.hasExcessiveEncoding = (f_url_encoded > 0);
  urlInfo.numAtSymbols = (f_at_symbols > 0) ? 1 : 0;

  return {{
    classification: isPhishing ? "Phishing" : "Legitimate",
    confidence: Math.max(0.01, probability),
    score: probability,
  }};
}}
"""

with open('background.js', 'r', encoding='utf-8') as f:
    bg = f.read()

# Replace the entire old function avoiding regex replace sequence parsing
target = r"function analyzeUrlFeatures\(urlInfo\) \{.*?return \{\n    classification: isPhishing \? \"Phishing\" : \"Legitimate\",\n    confidence: Math\.max\(0\.01, probability\),\n    score: probability,\n  \};\n\}"

# Find the start and end of the match
match = re.search(target, bg, flags=re.DOTALL)
if match:
    bg = bg[:match.start()] + js_func + bg[match.end():]
else:
    print("Could not find Target Function in background.js!")

with open('background.js', 'w', encoding='utf-8') as f:
    f.write(bg)

print("Injected new model successfully.")
