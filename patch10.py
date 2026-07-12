import re

with open('background.js', 'r', encoding='utf-8') as f:
    bg = f.read()

# 1. Remove the rigid hardcoded offline blocklist that the user opposed
bg = re.sub(r'const offlineBlocklist = new Set\(\[[\s\S]*?\]\);\n', '', bg)
bg = re.sub(r'if \(offlineBlocklist\.has\(urlInfo\.domain\)\) \{[\s\S]*?\}\s*if', 'if', bg)

# 2. Inject structural DOM scanner
dom_scanner = """async function fetchPageSignals(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200); // Super fast timeout
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);
    
    if (!response.ok) return { passwordField: false, externalForm: false, hiddenIframe: false };
    
    const html = await response.text();
    const signals = { passwordField: false, externalForm: false, hiddenIframe: false };
    
    // Check for deeply nested credential harvesters
    if (/<input[^>]*type=["']password["']/i.test(html)) {
      signals.passwordField = true;
    }
    
    // Look for data exfiltration endpoints in form actions
    const formMatch = html.match(/<form[^>]*action=["'](http[^"']+)["']/i);
    if (formMatch) {
      try {
        const targetUrl = new URL(formMatch[1]);
        const originUrl = new URL(url);
        if (targetUrl.hostname !== originUrl.hostname && !targetUrl.hostname.includes(originUrl.hostname)) {
          signals.externalForm = true;
        }
      } catch (e) {}
    }
    
    // Look for invisible overlay IFrames loading malicious domains
    if (/<iframe[^>]*(display:\s*none|visibility:\s*hidden|opacity:\s*0|width:\s*0|height:\s*0)[^>]*>/i.test(html)) {
      signals.hiddenIframe = true;
    }
    return signals;
  } catch (e) {
    return { passwordField: false, externalForm: false, hiddenIframe: false };
  }
}

function determineDomainCategory(url)"""

bg = bg.replace('function determineDomainCategory(url)', dom_scanner)


# 3. Hook DOM scanner into analyzeUrl
bg = re.sub(r'let domainAge = null;', 'let domainAge = null;\n  const domSignals = await fetchPageSignals(url);', bg)
bg = re.sub(r'return analyzeUrlFeatures\(urlInfo, domainAge, url\);', 'return analyzeUrlFeatures(urlInfo, domainAge, url, domSignals);', bg)

# 4. Integrate into Logistic Regression Subsystem
target_ml = r"function analyzeUrlFeatures\(urlInfo, domainAge, url\) \{\n  // ──────────────────────────────────────────────"
replace_ml = """function analyzeUrlFeatures(urlInfo, domainAge, url, domSignals) {
  urlInfo.domSignals = domSignals || { passwordField: false, externalForm: false, hiddenIframe: false };
  // ──────────────────────────────────────────────"""
bg = re.sub(target_ml, replace_ml, bg)

# 5. Extract structural ML Features
target_extract = r"// 1\. Feature Extraction \(Normalization\)"
replace_extract = """// 1. Feature Extraction (Normalization)
  const f_domPassword = urlInfo.domSignals.passwordField ? 1.0 : 0.0;
  const f_domExternal = urlInfo.domSignals.externalForm ? 1.0 : 0.0;
  const f_domHidden = urlInfo.domSignals.hiddenIframe ? 1.0 : 0.0;
  const f_domRisk = (f_domPassword && (urlInfo.category === 'unknown' || spoofedBrand)) ? 1.0 : 0.0;"""
bg = re.sub(target_extract, replace_extract, bg)

# 6. Apply Massive Weight Matrix mapping to DOM behaviors
target_matrix = r"const W_bias = -3\.5;([\s\S]*?)\];"
replace_matrix = """const W_bias = -4.0;\1,
    f_domPassword     * 3.5,   // Unexpected password forms
    f_domExternal     * 3.0,   // Data exfiltration to unknown domains
    f_domHidden       * 2.5,   // Obfuscated iframes
    f_domRisk         * 5.5    // Critical threat: Unknown/Spoofed domain asking for passwords!
  ];"""
bg = re.sub(target_matrix, replace_matrix, bg)

with open('background.js', 'w', encoding='utf-8') as f:
    f.write(bg)
