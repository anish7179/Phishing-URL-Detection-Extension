document.addEventListener("DOMContentLoaded", function () {
  // ── Tab switching ──
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const target = button.dataset.tab;
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabContents.forEach((c) => c.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(target).classList.add("active");

      if (target === "history") loadDetections();
      if (target === "settings") loadSettings();
      if (target === "statistics") loadStatistics();
    });
  });

  // ── Sensitivity display ──
  const sensitivitySlider = document.getElementById("sensitivity-level");
  const sensitivityDisplay = document.getElementById("sensitivity-display");
  sensitivitySlider.addEventListener("input", function () {
    sensitivityDisplay.textContent = this.value;
  });

  // ── Analyze URL button ──
  document.getElementById("analyze-btn").addEventListener("click", function () {
    const url = document.getElementById("url-input").value.trim();
    if (url) {
      showLoading(true);
      analyzeUrl(url);
    }
  });

  // Enter key trigger
  document
    .getElementById("url-input")
    .addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        const url = this.value.trim();
        if (url) {
          showLoading(true);
          analyzeUrl(url);
        }
      }
    });

  // ── Analyze Current Page ──
  document
    .getElementById("analyze-current-btn")
    .addEventListener("click", function () {
      chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs && tabs[0] && tabs[0].url) {
          const url = tabs[0].url;
          document.getElementById("url-input").value = url;
          showLoading(true);
          analyzeUrl(url);
        }
      });
    });

  // ── Settings ──
  document
    .querySelectorAll('#settings input[type="checkbox"]')
    .forEach((cb) => {
      cb.addEventListener("change", saveSettings);
    });
  sensitivitySlider.addEventListener("change", saveSettings);

  // ── Clear History ──
  document
    .getElementById("clear-history")
    .addEventListener("click", function () {
      chrome.runtime.sendMessage({ action: "clearDetections" }, function () {
        loadDetections();
      });
    });

  // ── Refresh Stats ──
  document
    .getElementById("refresh-stats")
    .addEventListener("click", function () {
      loadStatistics();
    });

  // ────────────────────────────────
  //  Loading / Scanner
  // ────────────────────────────────
  function showLoading(show) {
    const scanner = document.getElementById("loading");
    const resultCard = document.getElementById("result");
    if (show) {
      scanner.classList.add("active");
      resultCard.classList.remove("active");
    } else {
      scanner.classList.remove("active");
    }
  }

  // ────────────────────────────────
  //  Analyze URL
  // ────────────────────────────────
  function analyzeUrl(url) {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "http://" + url;
    }
    chrome.runtime.sendMessage(
      { action: "analyzeUrl", url: url, checkDomainAge: true },
      function (result) {
        showLoading(false);
        if (result) displayResult(result);
      },
    );
  }

  // ────────────────────────────────
  //  Display Result
  // ────────────────────────────────
  function displayResult(result) {
    const resultCard = document.getElementById("result");
    const isPhishing = result.classification === "Phishing";
    const confidence = (result.confidence * 100).toFixed(1);
    const gaugeColor = isPhishing ? "var(--danger)" : "var(--success)";
    const gaugeGlow = isPhishing ? "var(--danger-glow)" : "var(--success-glow)";
    const circumference = 2 * Math.PI * 30; // r=30 → ~188.5

    // Build risk factors from explanation
    const riskFactors = [];
    if (result.urlInfo) {
      if (result.urlInfo.hasSuspiciousWords)
        riskFactors.push("Contains suspicious keywords");
      if (result.urlInfo.hasIpAddress)
        riskFactors.push("Uses IP address instead of domain");
      if (result.urlInfo.domainLength > 30)
        riskFactors.push("Unusually long domain name");
      if (result.urlInfo.numDots > 3)
        riskFactors.push(
          `Excessive dots in domain (${result.urlInfo.numDots})`,
        );
      if (result.urlInfo.numHyphens > 2)
        riskFactors.push(`Multiple hyphens (${result.urlInfo.numHyphens})`);
      if (result.urlInfo.numAtSymbols > 0)
        riskFactors.push("Contains @ symbol (highly suspicious)");
      if (result.urlInfo.subdomainLevels > 2)
        riskFactors.push(
          `Deep subdomain nesting (${result.urlInfo.subdomainLevels} levels)`,
        );
    }
    if (result.domainAge && result.domainAge.isSuspicious) {
      riskFactors.push(
        `Recently registered domain (${result.domainAge.ageInDays} days old)`,
      );
    }
    if (result.phishingCount && result.phishingCount > 1) {
      riskFactors.push(
        `${result.phishingCount} phishing attempts from this domain`,
      );
    }

    // Category badge
    const category =
      result.category ||
      (result.urlInfo && result.urlInfo.category) ||
      "unknown";
    const categoryIcons = {
      financial: "🏦",
      ecommerce: "🛒",
      social: "👥",
      gaming: "🎮",
      education: "🎓",
      streaming: "🎬",
      technology: "💻",
      government: "🏛️",
      healthcare: "🏥",
      news: "📰",
      unknown: "🌐",
    };

    let html = `
      <div class="glass-card">
        <div class="result-header">
          <div class="gauge-wrap">
            <svg class="gauge-ring" viewBox="0 0 72 72">
              <circle class="gauge-bg" cx="36" cy="36" r="30"/>
              <circle class="gauge-fill" cx="36" cy="36" r="30"
                style="stroke: ${gaugeColor}; filter: drop-shadow(0 0 6px ${gaugeGlow});"/>
            </svg>
            <div class="gauge-text">
              <span class="gauge-value" style="color: ${gaugeColor};">${confidence}%</span>
              <span class="gauge-label">Confidence</span>
            </div>
          </div>
          <div class="result-info">
            <h2>${isPhishing ? "⚠️ Threat Detected" : "✅ URL is Safe"}</h2>
            <div class="result-domain">${result.urlInfo ? result.urlInfo.domain : result.url}</div>
            <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px;">
              <span class="result-badge ${isPhishing ? "badge-danger" : "badge-safe"}">
                ${isPhishing ? "🚫 Phishing" : "🔒 Legitimate"}
              </span>
              <span class="result-badge badge-category">
                ${categoryIcons[category] || "🌐"} ${category.charAt(0).toUpperCase() + category.slice(1)}
              </span>
            </div>
          </div>
        </div>`;

    // Domain age
    if (result.domainAge) {
      html += `
        <div class="domain-age-card">
          <span>Domain Age: <strong>${result.domainAge.ageInDays} days</strong></span>
          <span>Registered: <strong>${result.domainAge.registrationDate}</strong></span>
        </div>`;
    }

    // Risk factors
    if (riskFactors.length > 0) {
      html += `<div class="risk-section">
        <div class="risk-title">Risk Factors</div>
        <div class="risk-list">`;
      riskFactors.forEach((factor) => {
        html += `<div class="risk-item"><span class="risk-dot"></span>${factor}</div>`;
      });
      html += `</div></div>`;
    } else if (!isPhishing) {
      html += `<div class="risk-section">
        <div class="risk-title">Analysis</div>
        <div class="risk-list">
          <div class="risk-item safe-item"><span class="risk-dot"></span>No suspicious patterns detected</div>
          <div class="risk-item safe-item"><span class="risk-dot"></span>Domain structure looks normal</div>
        </div>
      </div>`;
    }

    html += `</div>`;

    resultCard.innerHTML = html;
    resultCard.classList.add("active");

    // Animate gauge
    requestAnimationFrame(() => {
      const gaugeFill = resultCard.querySelector(".gauge-fill");
      if (gaugeFill) {
        const offset = circumference - circumference * result.confidence;
        gaugeFill.style.strokeDashoffset = offset;
      }
    });
  }

  // ────────────────────────────────
  //  Load Detection History
  // ────────────────────────────────
  function loadDetections() {
    chrome.runtime.sendMessage(
      { action: "getDetections" },
      function (detections) {
        const list = document.getElementById("detections-list");
        if (!detections || detections.length === 0) {
          list.innerHTML = `
          <div class="empty-state">
            <div class="empty-icon">🛡️</div>
            <p>No threats detected yet</p>
          </div>`;
          return;
        }

        let html = "";
        detections.slice(0, 50).forEach((det) => {
          const isPhishing = det.classification === "Phishing";
          const time = new Date(det.timestamp).toLocaleString();
          const conf = det.confidence
            ? (det.confidence * 100).toFixed(1) + "%"
            : "N/A";
          const category = det.category || "unknown";
          const categoryIcons = {
            financial: "🏦",
            ecommerce: "🛒",
            social: "👥",
            gaming: "🎮",
            education: "🎓",
            streaming: "🎬",
            technology: "💻",
            government: "🏛️",
            healthcare: "🏥",
            news: "📰",
            unknown: "🌐",
          };

          html += `
          <div class="detection-card">
            <div class="detection-url">${det.url}</div>
            <div class="detection-meta">
              <span class="result-badge ${isPhishing ? "badge-danger" : "badge-safe"}">
                ${isPhishing ? "🚫 Phishing" : "🔒 Safe"} · ${conf}
              </span>
              <span class="result-badge badge-category">
                ${categoryIcons[category] || "🌐"} ${category}
              </span>
              <span class="detection-time">${time}</span>
            </div>
          </div>`;
        });

        list.innerHTML = html;
      },
    );
  }

  // ────────────────────────────────
  //  Load Settings
  // ────────────────────────────────
  function loadSettings() {
    chrome.storage.local.get("settings", function (data) {
      if (data.settings) {
        const s = data.settings;
        document.getElementById("real-time-protection").checked =
          s.realTimeProtection !== false;
        document.getElementById("show-warnings").checked =
          s.showWarnings !== false;
        document.getElementById("check-domain-age").checked =
          s.checkDomainAge !== false;
        document.getElementById("advanced-analysis").checked =
          s.advancedAnalysis !== false;
        if (s.sensitivityLevel) {
          sensitivitySlider.value = s.sensitivityLevel;
          sensitivityDisplay.textContent = s.sensitivityLevel;
        }
      }
    });
  }

  // ────────────────────────────────
  //  Save Settings
  // ────────────────────────────────
  function saveSettings() {
    const newSettings = {
      realTimeProtection: document.getElementById("real-time-protection")
        .checked,
      showWarnings: document.getElementById("show-warnings").checked,
      checkDomainAge: document.getElementById("check-domain-age").checked,
      advancedAnalysis: document.getElementById("advanced-analysis").checked,
      sensitivityLevel: parseInt(sensitivitySlider.value),
    };
    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: newSettings,
    });
  }

  // ────────────────────────────────
  //  Load Statistics
  // ────────────────────────────────
  function loadStatistics() {
    chrome.runtime.sendMessage(
      { action: "getAllPhishingStatistics" },
      function (stats) {
        if (!stats) return;

        // Total count with counter animation
        const totalEl = document.getElementById("total-count");
        animateCounter(totalEl, stats.totalPhishingAttempts || 0);

        // Category bar chart
        const catContainer = document.getElementById("category-statistics");
        const counts = stats.categoryCounts || {};
        const maxCount = Math.max(...Object.values(counts), 1);

        const categoryIcons = {
          financial: "🏦",
          ecommerce: "🛒",
          social: "👥",
          gaming: "🎮",
          education: "🎓",
          streaming: "🎬",
          technology: "💻",
          government: "🏛️",
          healthcare: "🏥",
          news: "📰",
          unknown: "🌐",
        };

        // Sort by count descending
        const sorted = Object.entries(counts)
          .filter(([k]) => k !== "unknown")
          .sort((a, b) => b[1] - a[1]);

        let catHtml = "";
        sorted.forEach(([cat, count]) => {
          const pct = (count / maxCount) * 100;
          const icon = categoryIcons[cat] || "🌐";
          catHtml += `
          <div class="bar-row">
            <span class="bar-label">${icon} ${cat}</span>
            <div class="bar-track">
              <div class="bar-fill" style="width: 0%;" data-width="${pct}%"></div>
            </div>
            <span class="bar-count">${count}</span>
          </div>`;
        });
        catContainer.innerHTML = catHtml;

        // Animate bars
        requestAnimationFrame(() => {
          catContainer.querySelectorAll(".bar-fill").forEach((bar) => {
            bar.style.width = bar.dataset.width;
          });
        });

        // Domain statistics
        const domContainer = document.getElementById("domain-statistics");
        const domainCounts = stats.domainCounts || {};
        const domSorted = Object.entries(domainCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 8);

        const domMax = domSorted.length > 0 ? domSorted[0][1] : 1;

        let domHtml = "";
        if (domSorted.length === 0) {
          domHtml =
            '<div class="empty-state"><p style="font-size:12px;">No domain data yet</p></div>';
        } else {
          domSorted.forEach(([domain, count]) => {
            const pct = (count / domMax) * 100;
            const shortDomain =
              domain.length > 12 ? domain.substring(0, 12) + "…" : domain;
            domHtml += `
            <div class="bar-row">
              <span class="bar-label" title="${domain}">${shortDomain}</span>
              <div class="bar-track">
                <div class="bar-fill" style="width: 0%; background: linear-gradient(90deg, var(--danger), #cc3344);" data-width="${pct}%"></div>
              </div>
              <span class="bar-count">${count}</span>
            </div>`;
          });
        }
        domContainer.innerHTML = domHtml;

        // Animate domain bars
        requestAnimationFrame(() => {
          domContainer.querySelectorAll(".bar-fill").forEach((bar) => {
            bar.style.width = bar.dataset.width;
          });
        });

        // Most targeted
        const mtSection = document.getElementById("most-targeted-section");
        const mtLabel = document.getElementById("most-targeted-category");
        if (stats.mostTargetedCategory && stats.mostTargetedCategory[1] > 0) {
          mtSection.style.display = "block";
          const icon = categoryIcons[stats.mostTargetedCategory[0]] || "🌐";
          mtLabel.textContent = `${icon} ${stats.mostTargetedCategory[0]} (${stats.mostTargetedCategory[1]} attempts)`;
        } else {
          mtSection.style.display = "none";
        }
      },
    );
  }

  // ── Counter Animation ──
  function animateCounter(el, target) {
    const duration = 800;
    const start = parseInt(el.textContent) || 0;
    const startTime = performance.now();

    function update(time) {
      const elapsed = time - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(start + (target - start) * eased);
      if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
  }

  // ── Initial loads ──
  loadSettings();

  // Pre-fill current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http")) {
      document.getElementById("url-input").value = tabs[0].url;
    }
  });
});
