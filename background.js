const suspiciousKeywords = [
  "login",
  "secure",
  "account",
  "verify",
  "update",
  "bank",
  "paypal",
  "amazon",
  "apple",
  "microsoft",
  "netflix",
  "password",
  "urgent",
  "suspended",
  "limited",
  "validation",
  "recovery",
  "security",
  "confirm",
];

const suspiciousPatterns = [
  /\d+\.[a-z]+\.[a-z]+/,
  /[0-9]{3,}\.[a-z]+/,
  /[a-z]+-[a-z]+\.[a-z]+/,
];

// Top brands for typosquatting checks
const topBrands = [
  "google",
  "youtube",
  "facebook",
  "amazon",
  "apple",
  "microsoft",
  "netflix",
  "paypal",
  "instagram",
  "twitter",
  "linkedin",
  "github",
  "yahoo",
  "whatsapp",
  "tiktok",
  "reddit",
  "twitch",
  "ebay",
  "walmart",
  "chase",
  "wellsfargo",
  "bankofamerica",
  "capitalone",
  "citi",
  "americanexpress",
];

// Built-in whitelist (Top trusted domains)
const builtInWhitelist = new Set([
  "google.com",
  "youtube.com",
  "facebook.com",
  "amazon.com",
  "wikipedia.org",
  "twitter.com",
  "instagram.com",
  "linkedin.com",
  "yahoo.com",
  "reddit.com",
  "github.com",
  "netflix.com",
  "bing.com",
  "paypal.com",
  "microsoft.com",
  "apple.com",
  "twitch.tv",
  "ebay.com",
  "stackoverflow.com",
  "duckduckgo.com",
]);

// Domain category keywords
const domainCategories = {
  education: [
    "university",
    "edu",
    "college",
    "academic",
    "school",
    "learning",
    "blackboard",
    "canvas",
    "moodle",
    "scholar",
    "edu.co",
    "academy",
    "institute",
    "seminar",
    "course",
    "education",
  ],
  ecommerce: [
    "ebay",
    "amazon",
    "shop",
    "store",
    "buy",
    "product",
    "mall",
    "market",
    "retail",
    "sale",
    "cart",
    "checkout",
    " order",
    "shopping",
    "alibaba",
    "walmart",
    "target",
    "merchant",
  ],
  social: [
    "facebook",
    "twitter",
    "instagram",
    "linkedin",
    "tiktok",
    "social",
    "friend",
    "connect",
    "network",
    "chat",
    "messenger",
    "whatsapp",
    "snapchat",
    "pinterest",
    "reddit",
    "telegram",
    "discord",
  ],
  financial: [
    "bank",
    "paypal",
    "crypto",
    "wallet",
    "payment",
    "finance",
    "credit",
    "debit",
    "loan",
    "money",
    "investment",
    "stock",
    "bitcoin",
    "blockchain",
    "card",
    "visa",
    "mastercard",
    "exchange",
  ],
  gaming: [
    "game",
    "steam",
    "epic",
    "origin",
    "battle",
    "league",
    "fortnite",
    "minecraft",
    "xbox",
    "playstation",
    "nintendo",
    "esports",
    "blizzard",
    "riot",
    "valve",
    "gaming",
  ],
  streaming: [
    "netflix",
    "amazon prime",
    "hulu",
    "disney",
    "youtube",
    "twitch",
    "vimeo",
    "paramount",
    "stream",
    "watch",
    "video",
    "movie",
    "tv",
    "series",
    "episode",
    "crunchyroll",
  ],
  technology: [
    "microsoft",
    "apple",
    "google",
    "icloud",
    "dropbox",
    "drive",
    "office",
    "adobe",
    "software",
    "tech",
    "support",
    "update",
    "download",
    "windows",
    "macos",
    "android",
    "ios",
  ],
  government: [
    "gov",
    "government",
    "federal",
    "state",
    "city",
    "municipality",
    "agency",
    "department",
    "public",
    "passport",
    "tax",
    "service",
    "military",
    "court",
    "justice",
    "official",
  ],
  healthcare: [
    "health",
    "medical",
    "doctor",
    "hospital",
    "clinic",
    "pharmacy",
    "medicine",
    "patient",
    "healthcare",
    "insurance",
    "treatment",
    "diagnosis",
    "nursing",
    "covid",
    "vaccine",
  ],
  news: [
    "news",
    "media",
    "article",
    "journal",
    "magazine",
    "press",
    "daily",
    "times",
    "post",
    "herald",
    "tribune",
    "cnn",
    "bbc",
    "reuters",
    "associated press",
    "blog",
  ],
};

let settings = {
  realTimeProtection: true,
  showWarnings: true,
  checkDomainAge: true,
  advancedAnalysis: true,
  sensitivityLevel: 3,
  safeBrowsingKey: "",
  customWhitelist: "",
};

let domainPhishingCounts = {};
let categoryPhishingCounts = {
  education: 0,
  ecommerce: 0,
  social: 0,
  financial: 0,
  gaming: 0,
  streaming: 0,
  technology: 0,
  government: 0,
  healthcare: 0,
  news: 0,
  unknown: 0,
};

// ── Startup ──
chrome.storage.local.get(
  ["settings", "domainPhishingCounts", "categoryPhishingCounts"],
  (data) => {
    if (data.settings) settings = { ...settings, ...data.settings };
    if (data.domainPhishingCounts)
      domainPhishingCounts = data.domainPhishingCounts;
    if (data.categoryPhishingCounts)
      categoryPhishingCounts = data.categoryPhishingCounts;
  },
);

// ── Helper Extractors ──
function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./i, "");
  } catch (e) {
    const matches = url.match(
      /^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/i,
    );
    return matches ? matches[1] : url;
  }
}

function determineDomainCategory(url) {
  const domain = extractDomain(url).toLowerCase();
  const urlLower = url.toLowerCase();
  for (const [category, keywords] of Object.entries(domainCategories)) {
    if (keywords.some((kw) => domain.includes(kw) || urlLower.includes(kw)))
      return category;
  }
  return "unknown";
}

// ── Advanced ML-Like Heuristic Functions ──

// Shannon Entropy
function shannonEntropy(str) {
  const len = str.length;
  if (len === 0) return 0;
  const chars = {};
  for (let i = 0; i < len; i++) {
    chars[str[i]] = (chars[str[i]] || 0) + 1;
  }
  return Object.values(chars).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);
}

// Levenshtein Distance (Typosquatting)
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      if (a[i - 1] === b[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1,
        );
      }
    }
  }
  return matrix[a.length][b.length];
}

// Check Typosquatting against Top Brands
function checkTyposquatting(domain) {
  const tldless = domain.substring(0, domain.lastIndexOf("."));
  const baseName =
    tldless.indexOf(".") > -1 ? tldless.split(".").pop() : tldless;
  if (baseName.length < 4) return false;

  for (const brand of topBrands) {
    if (baseName === brand) return false; // Exact match on name goes to whitelisting check usually, but if not whitelisted it's spoofing TLD
    const dist = levenshteinDistance(baseName, brand);
    // If it's off by exactly 1 character (swap, drop, add) from a major brand, extremely high risk
    if (dist === 1) return brand;
  }
  return false;
}

// Homoglyphs Check
function checkHomoglyphs(domain) {
  // Looks for punycode or cyrillic/greek mix
  return domain.includes("xn--") || /[а-яА-Яα-ωΑ-Ω]/.test(domain);
}

// ── RDAP (WHOIS) Domain Age ──
async function checkDomainAgeReal(domain) {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { Accept: "application/rdap+json" },
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error("RDAP query failed");
    const data = await res.json();
    const regEvent = data.events?.find((e) => e.eventAction === "registration");
    if (regEvent && regEvent.eventDate) {
      const regDate = new Date(regEvent.eventDate);
      const ageInDays = Math.floor(
        (Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24),
      );
      return {
        domain,
        ageInDays,
        registrationDate: regDate.toISOString().split("T")[0],
        isSuspicious: ageInDays < 30,
      };
    }
  } catch (e) {
    console.error("RDAP domain age error:", e);
  }
  // Fallback / graceful degradation if RDAP fails (or returns generic error)
  return {
    domain,
    ageInDays: "Unknown",
    registrationDate: "Unknown",
    isSuspicious: false,
  };
}

// ── URL Analysis Pipeline ──
function preprocessUrl(url) {
  try {
    if (typeof URL === "undefined") return fallbackPreprocess(url);
    if (!url.startsWith("http://") && !url.startsWith("https://"))
      url = "http://" + url;

    const urlObj = new URL(url);
    const domain = urlObj.hostname.replace(/^www\./i, "");
    const path = urlObj.pathname;

    return {
      url,
      domain,
      path,
      category: determineDomainCategory(url),
      domainLength: domain.length,
      pathLength: path.length,
      hasSuspiciousWords: suspiciousKeywords.some((w) =>
        url.toLowerCase().includes(w),
      ),
      hasIpAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(domain),
      numDots: domain.split(".").length - 1,
      numHyphens: domain.split("-").length - 1,
      numAtSymbols: url.split("@").length - 1, // Look at full URL for @
      hasExcessiveEncoding: (url.match(/%[0-9a-fA-F]{2}/g) || []).length > 5, // URL Encoding detection
      subdomainLevels: domain.split(".").length - 2,
    };
  } catch (e) {
    return fallbackPreprocess(url);
  }
}

function fallbackPreprocess(url) {
  return {
    url,
    domain: extractDomain(url),
    path: "",
    category: "unknown",
    domainLength: 0,
    pathLength: 0,
    hasSuspiciousWords: false,
    hasIpAddress: false,
    numDots: 0,
    numHyphens: 0,
    numAtSymbols: 0,
    hasExcessiveEncoding: false,
    subdomainLevels: 0,
  };
}

function analyzeUrlFeatures(urlInfo) {
  let score = 0.0;
  const sensMultiplier = settings.sensitivityLevel / 3;

  if (urlInfo.hasSuspiciousWords) score += 0.4 * sensMultiplier;
  if (urlInfo.domainLength > 35) score += 0.3 * sensMultiplier;
  if (urlInfo.numHyphens > 2) score += 0.3 * sensMultiplier;
  if (urlInfo.hasIpAddress) score += 0.6 * sensMultiplier;
  if (urlInfo.numAtSymbols > 0) score += 0.5 * sensMultiplier;
  if (urlInfo.hasExcessiveEncoding) score += 0.2 * sensMultiplier;

  if (suspiciousPatterns.some((p) => p.test(urlInfo.url.toLowerCase()))) {
    score += 0.3 * sensMultiplier;
  }

  const domainEntropy = shannonEntropy(urlInfo.domain);
  if (domainEntropy > 4.0) {
    // Highly randomized domains
    score += 0.35 * sensMultiplier;
  }

  const spoofedBrand = checkTyposquatting(urlInfo.domain);
  if (spoofedBrand) {
    urlInfo.spoofedBrand = spoofedBrand; // Save for explanation
    score += 0.6 * sensMultiplier;
  }

  if (checkHomoglyphs(urlInfo.domain)) {
    urlInfo.hasHomoglyphs = true;
    score += 0.65 * Math.max(1, sensMultiplier);
  }

  const suspiciousTLDs = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".zip",
    ".click",
    ".link",
  ];
  if (suspiciousTLDs.some((tld) => urlInfo.domain.endsWith(tld))) {
    score += 0.25 * sensMultiplier;
  }

  if (urlInfo.domainAge && urlInfo.domainAge.isSuspicious) {
    score += 0.3 * sensMultiplier;
  }

  score = Math.min(score, 0.99);

  const threshold = 0.35 - (settings.sensitivityLevel - 3) * 0.05;
  const isPhishing = score > threshold;

  return {
    classification: isPhishing ? "Phishing" : "Legitimate",
    confidence: isPhishing ? score : 1 - score / threshold,
    score: score,
  };
}

// ── Check Whitelist ──
function isDomainWhitelisted(domain) {
  if (builtInWhitelist.has(domain)) return true;
  if (!settings.customWhitelist) return false;
  const customList = settings.customWhitelist
    .split("\n")
    .map((d) => d.trim().toLowerCase())
    .filter((d) => !!d);
  return customList.some(
    (trusted) => domain === trusted || domain.endsWith("." + trusted),
  );
}

// ── Main Analysis Execution ──
async function analyzeUrl(url, checkAgeOpt = true) {
  const urlInfo = preprocessUrl(url);

  // 1. Whitelist Fast-path Check
  if (isDomainWhitelisted(urlInfo.domain)) {
    return buildWhitelistedResult(url, urlInfo);
  }

  // 2. Fetch Data (RDAP)
  let agePromise =
    settings.checkDomainAge && checkAgeOpt
      ? checkDomainAgeReal(urlInfo.domain)
      : Promise.resolve(null);

  const domainAge = await agePromise;
  urlInfo.domainAge = domainAge;

  // 3. Analytics & Score Calculation
  const result = analyzeUrlFeatures(urlInfo);

  // Attach Historical Counts
  urlInfo.phishingCount = domainPhishingCounts[urlInfo.domain] || 0;
  urlInfo.categoryPhishingCount = categoryPhishingCounts[urlInfo.category] || 0;

  // Generate user explanation
  const explanation = explainPrediction(url, result, urlInfo);

  return {
    url,
    classification: result.classification,
    confidence: result.confidence,
    score: result.score,
    explanation,
    urlInfo,
    domainAge,
    phishingCount: urlInfo.phishingCount,
    categoryPhishingCount: urlInfo.categoryPhishingCount,
    category: urlInfo.category,
  };
}

function buildWhitelistedResult(url, urlInfo) {
  return {
    url,
    classification: "Legitimate",
    confidence: 1.0,
    score: 0.0,
    explanation: "This website is in your trusted domains whitelist.",
    urlInfo,
    domainAge: null,
    phishingCount: 0,
    categoryPhishingCount: categoryPhishingCounts[urlInfo.category] || 0,
    category: urlInfo.category,
    isWhitelisted: true,
  };
}

function explainPrediction(url, result, urlInfo) {
  let exp = `URL classified as ${result.classification} (${(result.confidence * 100).toFixed(1)}% confidence).\n\n`;
  const risks = [];

  if (urlInfo.isSafeBrowsingHit)
    risks.push("Google Safe Browsing explicitly flagged this URL.");
  if (urlInfo.spoofedBrand)
    risks.push(
      `Typosquatting detected (Impersonating '${urlInfo.spoofedBrand}').`,
    );
  if (urlInfo.hasHomoglyphs)
    risks.push(
      "Contains deceptive Unicode/Cyrillic characters (Homoglyph spoofing).",
    );
  if (shannonEntropy(urlInfo.domain) > 4.0)
    risks.push("Domain name has highly randomized characters (High Entropy).");
  if (urlInfo.hasExcessiveEncoding)
    risks.push("Excessive URL encoding to obfuscate real destination.");
  if (urlInfo.hasSuspiciousWords)
    risks.push("Contains common phishing keywords (e.g. login, verify).");
  if (urlInfo.hasIpAddress)
    risks.push("Uses IP address instead of legitimate domain.");
  if (urlInfo.numAtSymbols > 0)
    risks.push("Contains '@' symbol (Credential harvesting tactic).");
  if (urlInfo.domainAge && urlInfo.domainAge.isSuspicious)
    risks.push(
      `Domain is extremely new (Registered ${urlInfo.domainAge.ageInDays} days ago).`,
    );
  if (domainPhishingCounts[urlInfo.domain] >= 2)
    risks.push(
      `You have previously seen ${domainPhishingCounts[urlInfo.domain]} threats from this domain.`,
    );

  if (risks.length > 0) {
    exp += "Risk Factors:\n" + risks.map((r) => "- " + r).join("\n");
  } else {
    exp += "No distinct risk factors identified.";
  }
  return exp;
}

function updateDomainPhishingCount(domain, category) {
  domainPhishingCounts[domain] = (domainPhishingCounts[domain] || 0) + 1;
  if (category && categoryPhishingCounts.hasOwnProperty(category)) {
    categoryPhishingCounts[category]++;
  } else {
    categoryPhishingCounts.unknown++;
  }
  chrome.storage.local.set({ domainPhishingCounts, categoryPhishingCounts });
}

// ── Listeners ──
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (!settings.realTimeProtection || !details.url.startsWith("http")) return;

  const result = await analyzeUrl(details.url);
  if (
    result.classification === "Phishing" &&
    result.confidence > 0.5 &&
    settings.showWarnings
  ) {
    chrome.tabs
      .sendMessage(details.tabId, { action: "showWarning", data: result })
      .catch(() => null);
    updateDomainPhishingCount(result.urlInfo.domain, result.urlInfo.category);

    chrome.storage.local.get("detections", (data) => {
      const detections = data.detections || [];
      detections.unshift({
        // Add to top
        url: details.url,
        timestamp: new Date().toISOString(),
        classification: result.classification,
        confidence: result.confidence,
        domainAge: result.domainAge,
        category: result.urlInfo.category,
        domain: result.urlInfo.domain,
        phishingCount: domainPhishingCounts[result.urlInfo.domain] || 1,
      });
      if (detections.length > 100) detections.pop();
      chrome.storage.local.set({ detections });
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyzeUrl") {
    analyzeUrl(message.url, message.checkDomainAge).then((result) => {
      if (result.classification === "Phishing" && result.confidence > 0.5) {
        if (result.urlInfo?.domain)
          updateDomainPhishingCount(
            result.urlInfo.domain,
            result.urlInfo.category,
          );
      }
      sendResponse(result);
    });
    return true;
  }

  if (message.action === "getDetections") {
    chrome.storage.local.get("detections", (d) =>
      sendResponse(d.detections || []),
    );
    return true;
  }

  if (message.action === "clearDetections") {
    chrome.storage.local.set({ detections: [] }, () =>
      sendResponse({ success: true }),
    );
    return true;
  }

  if (message.action === "updateSettings") {
    settings = { ...settings, ...message.settings };
    chrome.storage.local.set({ settings }, () =>
      sendResponse({ success: true }),
    );
    return true;
  }

  if (message.action === "getAllPhishingStatistics") {
    const totalPhishingAttempts = Object.values(categoryPhishingCounts).reduce(
      (a, b) => a + b,
      0,
    );
    sendResponse({
      domainCounts: domainPhishingCounts,
      categoryCounts: categoryPhishingCounts,
      totalPhishingAttempts,
      mostTargetedCategory: Object.entries(categoryPhishingCounts).sort(
        (a, b) => b[1] - a[1],
      )[0],
    });
    return true;
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(["settings", "categoryPhishingCounts"], (data) => {
    if (!data.settings) chrome.storage.local.set({ settings });
    if (!data.categoryPhishingCounts)
      chrome.storage.local.set({ categoryPhishingCounts });
  });
});
