document.addEventListener("DOMContentLoaded", function () {
  // ── Theme Toggle ──
  const themeBtn = document.getElementById("theme-toggle");
  const html = document.documentElement;

  // Load saved theme
  chrome.storage.local.get("theme", function (data) {
    const saved = data.theme || "light";
    html.setAttribute("data-theme", saved);
    themeBtn.textContent = saved === "dark" ? "☀️" : "🌙";
  });

  themeBtn.addEventListener("click", function () {
    const current = html.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", next);
    themeBtn.textContent = next === "dark" ? "☀️" : "🌙";
    chrome.storage.local.set({ theme: next });
  });

  // ── Tab Switching ──
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

  // ── Sensitivity Display ──
  const sensitivitySlider = document.getElementById("sensitivity-level");
  const sensitivityDisplay = document.getElementById("sensitivity-display");
  sensitivitySlider.addEventListener("input", function () {
    sensitivityDisplay.textContent = this.value;
  });

  // ── Analyze URL ──
  document.getElementById("analyze-btn").addEventListener("click", function () {
    const url = document.getElementById("url-input").value.trim();
    if (url) {
      showLoading(true);
      analyzeUrl(url);
    }
  });

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
          document.getElementById("url-input").value = tabs[0].url;
          showLoading(true);
          analyzeUrl(tabs[0].url);
        }
      });
    });

  // ── Settings Handlers ──
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
      chrome.runtime.sendMessage({ action: "clearDetections" }, () =>
        loadDetections(),
      );
    });

  // ── Refresh Stats ──
  document
    .getElementById("refresh-stats")
    .addEventListener("click", () => loadStatistics());

  // ───────────────────────────
  //  Helpers
  // ───────────────────────────

  function showLoading(show) {
    document.getElementById("loading").classList.toggle("active", show);
    if (show) document.getElementById("result").classList.remove("active");
  }

  function analyzeUrl(url) {
    if (!url.startsWith("http://") && !url.startsWith("https://"))
      url = "http://" + url;
    chrome.runtime.sendMessage(
      { action: "analyzeUrl", url: url, checkDomainAge: true },
      function (result) {
        showLoading(false);
        if (result) displayResult(result);
      },
    );
  }

  const catIcons = {
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

  // ───────────────────────────
  //  Display Result
  // ───────────────────────────
  function displayResult(result) {
    const el = document.getElementById("result");
    const bad = result.classification === "Phishing";
    const conf = (result.confidence * 100).toFixed(1);
    const category =
      result.category ||
      (result.urlInfo && result.urlInfo.category) ||
      "unknown";
    const domain = result.urlInfo ? result.urlInfo.domain : result.url;

    // Risk factors
    const risks = [];
    if (result.urlInfo) {
      if (result.urlInfo.hasSuspiciousWords)
        risks.push("Contains suspicious keywords");
      if (result.urlInfo.hasIpAddress)
        risks.push("Uses IP address instead of domain");
      if (result.urlInfo.domainLength > 30)
        risks.push("Unusually long domain name");
      if (result.urlInfo.numDots > 3) risks.push("Excessive dots in domain");
      if (result.urlInfo.numHyphens > 2)
        risks.push("Multiple hyphens in domain");
      if (result.urlInfo.numAtSymbols > 0) risks.push("Contains @ symbol");
      if (result.urlInfo.subdomainLevels > 2)
        risks.push("Deep subdomain nesting");
    }
    if (result.domainAge && result.domainAge.isSuspicious)
      risks.push(
        "Recently registered domain (" + result.domainAge.ageInDays + " days)",
      );
    if (result.phishingCount > 1)
      risks.push(
        result.phishingCount + " prior phishing attempts from this domain",
      );

    let html = `<div class="card">
      <div class="result-status">
        <div class="result-icon ${bad ? "danger" : "safe"}">${bad ? "⚠️" : "✓"}</div>
        <div>
          <div class="result-title">${bad ? "Threat Detected" : "URL is Safe"}</div>
          <div class="result-domain">${domain}</div>
        </div>
      </div>

      <div class="confidence-row">
        <span class="confidence-label">Confidence</span>
        <span class="confidence-value" style="color: ${bad ? "var(--danger)" : "var(--success)"};">${conf}%</span>
      </div>
      <div class="confidence-track">
        <div class="confidence-fill" style="width: 0%; background: ${bad ? "var(--danger)" : "var(--success)"};"></div>
      </div>

      <div class="badges-row">
        <span class="badge ${bad ? "badge-danger" : "badge-safe"}">${bad ? "Phishing" : "Legitimate"}</span>
        <span class="badge badge-info">${catIcons[category] || "🌐"} ${category}</span>
      </div>`;

    // Domain age
    if (result.domainAge) {
      html += `<div class="domain-age-row">
        <span>Domain age: <strong>${result.domainAge.ageInDays} days</strong></span>
        <span>Registered: <strong>${result.domainAge.registrationDate}</strong></span>
      </div>`;
    }

    // Factors
    if (risks.length > 0) {
      html += `<div class="detail-section"><div class="detail-label">Risk Factors</div>`;
      risks.forEach((r) => {
        html += `<div class="detail-item"><span class="detail-dot dot-danger"></span>${r}</div>`;
      });
      html += `</div>`;
    } else if (!bad) {
      html += `<div class="detail-section"><div class="detail-label">Analysis</div>
        <div class="detail-item"><span class="detail-dot dot-safe"></span>No suspicious patterns found</div>
        <div class="detail-item"><span class="detail-dot dot-safe"></span>Domain structure is normal</div>
      </div>`;
    }

    html += `</div>`;
    el.innerHTML = html;
    el.classList.add("active");

    // Animate confidence bar
    requestAnimationFrame(() => {
      const fill = el.querySelector(".confidence-fill");
      if (fill) fill.style.width = conf + "%";
    });
  }

  // ───────────────────────────
  //  History
  // ───────────────────────────
  function loadDetections() {
    chrome.runtime.sendMessage(
      { action: "getDetections" },
      function (detections) {
        const list = document.getElementById("detections-list");
        if (!detections || detections.length === 0) {
          list.innerHTML =
            '<div class="empty-state"><p>No detections yet</p></div>';
          return;
        }

        let html = "";
        detections.slice(0, 50).forEach((d) => {
          const bad = d.classification === "Phishing";
          const conf = d.confidence
            ? (d.confidence * 100).toFixed(1) + "%"
            : "";
          const cat = d.category || "unknown";
          const time = new Date(d.timestamp).toLocaleString();

          html += `<div class="detection-item">
          <div class="det-url">${d.url}</div>
          <div class="det-meta">
            <span class="badge ${bad ? "badge-danger" : "badge-safe"}">${bad ? "Phishing" : "Safe"} ${conf}</span>
            <span class="badge badge-info">${catIcons[cat] || "🌐"} ${cat}</span>
            <span class="det-time">${time}</span>
          </div>
        </div>`;
        });
        list.innerHTML = html;
      },
    );
  }

  // ───────────────────────────
  //  Settings
  // ───────────────────────────
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

  function saveSettings() {
    const s = {
      realTimeProtection: document.getElementById("real-time-protection")
        .checked,
      showWarnings: document.getElementById("show-warnings").checked,
      checkDomainAge: document.getElementById("check-domain-age").checked,
      advancedAnalysis: document.getElementById("advanced-analysis").checked,
      sensitivityLevel: parseInt(sensitivitySlider.value),
    };
    chrome.runtime.sendMessage({ action: "updateSettings", settings: s });
  }

  // ───────────────────────────
  //  Statistics
  // ───────────────────────────
  function loadStatistics() {
    chrome.runtime.sendMessage(
      { action: "getAllPhishingStatistics" },
      function (stats) {
        if (!stats) return;

        // Total
        const totalEl = document.getElementById("total-count");
        animateCounter(totalEl, stats.totalPhishingAttempts || 0);

        // Category bars
        const catEl = document.getElementById("category-statistics");
        const counts = stats.categoryCounts || {};
        const maxC = Math.max(...Object.values(counts), 1);
        const sorted = Object.entries(counts)
          .filter(([k]) => k !== "unknown")
          .sort((a, b) => b[1] - a[1]);

        let catHtml = "";
        sorted.forEach(([cat, count]) => {
          const pct = (count / maxC) * 100;
          const icon = catIcons[cat] || "🌐";
          catHtml += `<div class="bar-row">
          <span class="bar-name">${icon} ${cat}</span>
          <div class="bar-track"><div class="bar-fill" style="width:0%;" data-w="${pct}%"></div></div>
          <span class="bar-val">${count}</span>
        </div>`;
        });
        catEl.innerHTML = catHtml;
        requestAnimationFrame(() =>
          catEl
            .querySelectorAll(".bar-fill")
            .forEach((b) => (b.style.width = b.dataset.w)),
        );

        // Domain bars
        const domEl = document.getElementById("domain-statistics");
        const domCounts = stats.domainCounts || {};
        const domSorted = Object.entries(domCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 6);
        const domMax = domSorted.length > 0 ? domSorted[0][1] : 1;

        let domHtml = "";
        if (domSorted.length === 0) {
          domHtml =
            '<div class="empty-state"><p style="font-size:12px;">No data yet</p></div>';
        } else {
          domSorted.forEach(([dom, count]) => {
            const pct = (count / domMax) * 100;
            const short = dom.length > 14 ? dom.substring(0, 14) + "…" : dom;
            domHtml += `<div class="bar-row">
            <span class="bar-name" title="${dom}">${short}</span>
            <div class="bar-track"><div class="bar-fill danger" style="width:0%;" data-w="${pct}%"></div></div>
            <span class="bar-val">${count}</span>
          </div>`;
          });
        }
        domEl.innerHTML = domHtml;
        requestAnimationFrame(() =>
          domEl
            .querySelectorAll(".bar-fill")
            .forEach((b) => (b.style.width = b.dataset.w)),
        );

        // Most targeted
        const mtBox = document.getElementById("most-targeted-section");
        const mtLabel = document.getElementById("most-targeted-category");
        if (stats.mostTargetedCategory && stats.mostTargetedCategory[1] > 0) {
          mtBox.style.display = "block";
          const icon = catIcons[stats.mostTargetedCategory[0]] || "🌐";
          mtLabel.textContent =
            icon +
            " " +
            stats.mostTargetedCategory[0] +
            " (" +
            stats.mostTargetedCategory[1] +
            ")";
        } else {
          mtBox.style.display = "none";
        }
      },
    );
  }

  function animateCounter(el, target) {
    const duration = 600;
    const start = parseInt(el.textContent) || 0;
    const t0 = performance.now();
    function step(t) {
      const p = Math.min((t - t0) / duration, 1);
      el.textContent = Math.round(
        start + (target - start) * (1 - Math.pow(1 - p, 3)),
      );
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ── Init ──
  loadSettings();
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http")) {
      document.getElementById("url-input").value = tabs[0].url;
    }
  });
});
