document.addEventListener("DOMContentLoaded", function () {
  // ── Theme Toggle ──
  const themeBtn = document.getElementById("theme-toggle");
  const html = document.documentElement;

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

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      tabButtons.forEach((b) => b.classList.remove("active"));
      tabContents.forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(target).classList.add("active");
      if (target === "history") loadDetections();
      if (target === "settings") loadSettings();
      if (target === "statistics") loadStatistics();
    });
  });

  // ── Sensitivity ──
  const slider = document.getElementById("sensitivity-level");
  const sliderDisp = document.getElementById("sensitivity-display");
  slider.addEventListener(
    "input",
    () => (sliderDisp.textContent = slider.value),
  );

  // ── Buttons ──
  document.getElementById("analyze-btn").addEventListener("click", () => {
    const url = document.getElementById("url-input").value.trim();
    if (url) {
      showLoading(true);
      analyzeUrl(url);
    }
  });

  document.getElementById("url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const url = e.target.value.trim();
      if (url) {
        showLoading(true);
        analyzeUrl(url);
      }
    }
  });

  document
    .getElementById("analyze-current-btn")
    .addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
          document.getElementById("url-input").value = tabs[0].url;
          showLoading(true);
          analyzeUrl(tabs[0].url);
        }
      });
    });

  document
    .querySelectorAll('#settings input[type="checkbox"]')
    .forEach((cb) => cb.addEventListener("change", saveSettings));
  slider.addEventListener("change", saveSettings);

  document
    .getElementById("clear-history")
    .addEventListener("click", () =>
      chrome.runtime.sendMessage({ action: "clearDetections" }, () =>
        loadDetections(),
      ),
    );

  document
    .getElementById("refresh-stats")
    .addEventListener("click", () => loadStatistics());

  // ─────────────────────
  //  Helpers
  // ─────────────────────

  function showLoading(show) {
    document.getElementById("loading").classList.toggle("active", show);
    if (show) document.getElementById("result").classList.remove("active");
  }

  function analyzeUrl(url) {
    if (!url.startsWith("http://") && !url.startsWith("https://"))
      url = "http://" + url;
    chrome.runtime.sendMessage(
      { action: "analyzeUrl", url, checkDomainAge: true },
      (result) => {
        showLoading(false);
        if (result) displayResult(result);
      },
    );
  }

  const icons = {
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

  // ─────────────────────
  //  Result Display
  // ─────────────────────
  function displayResult(r) {
    const el = document.getElementById("result");
    const bad = r.classification === "Phishing";
    const conf = (r.confidence * 100).toFixed(1);
    const cat = r.category || (r.urlInfo && r.urlInfo.category) || "unknown";
    const dom = r.urlInfo ? r.urlInfo.domain : r.url;

    const risks = [];
    if (r.urlInfo) {
      if (r.urlInfo.hasSuspiciousWords)
        risks.push("Contains suspicious keywords");
      if (r.urlInfo.hasIpAddress)
        risks.push("Uses IP address instead of domain");
      if (r.urlInfo.domainLength > 30) risks.push("Unusually long domain name");
      if (r.urlInfo.numDots > 3) risks.push("Excessive dots in domain");
      if (r.urlInfo.numHyphens > 2) risks.push("Multiple hyphens in domain");
      if (r.urlInfo.numAtSymbols > 0) risks.push("Contains @ symbol");
      if (r.urlInfo.subdomainLevels > 2) risks.push("Deep subdomain nesting");
    }
    if (r.domainAge && r.domainAge.isSuspicious)
      risks.push("Recently registered (" + r.domainAge.ageInDays + " days)");
    if (r.phishingCount > 1)
      risks.push(r.phishingCount + " prior attempts from this domain");

    let h = `<div class="card-3d">
      <div class="result-hero">
        <div class="result-ring ${bad ? "is-danger" : "is-safe"}">${bad ? "⚠️" : "✓"}</div>
        <div>
          <div class="result-title">${bad ? "Threat Detected" : "URL is Safe"}</div>
          <div class="result-domain">${dom}</div>
        </div>
      </div>
      <div class="conf-row">
        <span class="conf-label">Confidence</span>
        <span class="conf-val" style="color:${bad ? "var(--danger)" : "var(--success)"}">${conf}%</span>
      </div>
      <div class="conf-track">
        <div class="conf-fill ${bad ? "danger-fill" : "safe-fill"}" style="width:0%"></div>
      </div>
      <div class="badges-row">
        <span class="badge ${bad ? "badge-danger" : "badge-safe"}">${bad ? "Phishing" : "Legitimate"}</span>
        <span class="badge badge-info">${icons[cat] || "🌐"} ${cat}</span>
      </div>`;

    if (r.domainAge) {
      h += `<div class="age-row">
        <span>Age: <strong>${r.domainAge.ageInDays} days</strong></span>
        <span>Registered: <strong>${r.domainAge.registrationDate}</strong></span>
      </div>`;
    }

    if (risks.length > 0) {
      h +=
        '<div class="detail-section"><div class="detail-label">Risk Factors</div>';
      risks.forEach(
        (f) =>
          (h += `<div class="detail-item"><span class="d-dot dot-danger"></span>${f}</div>`),
      );
      h += "</div>";
    } else if (!bad) {
      h += `<div class="detail-section"><div class="detail-label">Analysis</div>
        <div class="detail-item"><span class="d-dot dot-safe"></span>No suspicious patterns found</div>
        <div class="detail-item"><span class="d-dot dot-safe"></span>Domain structure is normal</div>
      </div>`;
    }

    h += "</div>";
    el.innerHTML = h;
    el.classList.add("active");

    requestAnimationFrame(() => {
      const fill = el.querySelector(".conf-fill");
      if (fill) fill.style.width = conf + "%";
    });
  }

  // ─────────────────────
  //  History
  // ─────────────────────
  function loadDetections() {
    chrome.runtime.sendMessage({ action: "getDetections" }, (dets) => {
      const list = document.getElementById("detections-list");
      if (!dets || !dets.length) {
        list.innerHTML =
          '<div class="empty-state"><p>No detections yet</p></div>';
        return;
      }
      let h = "";
      dets.slice(0, 50).forEach((d) => {
        const bad = d.classification === "Phishing";
        const conf = d.confidence ? (d.confidence * 100).toFixed(1) + "%" : "";
        const cat = d.category || "unknown";
        h += `<div class="det-card">
          <div class="det-url">${d.url}</div>
          <div class="det-meta">
            <span class="badge ${bad ? "badge-danger" : "badge-safe"}">${bad ? "Phishing" : "Safe"} ${conf}</span>
            <span class="badge badge-info">${icons[cat] || "🌐"} ${cat}</span>
            <span class="det-time">${new Date(d.timestamp).toLocaleString()}</span>
          </div>
        </div>`;
      });
      list.innerHTML = h;
    });
  }

  // ─────────────────────
  //  Settings
  // ─────────────────────
  function loadSettings() {
    chrome.storage.local.get("settings", (data) => {
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
          slider.value = s.sensitivityLevel;
          sliderDisp.textContent = s.sensitivityLevel;
        }
      }
    });
  }

  function saveSettings() {
    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: {
        realTimeProtection: document.getElementById("real-time-protection")
          .checked,
        showWarnings: document.getElementById("show-warnings").checked,
        checkDomainAge: document.getElementById("check-domain-age").checked,
        advancedAnalysis: document.getElementById("advanced-analysis").checked,
        sensitivityLevel: parseInt(slider.value),
      },
    });
  }

  // ─────────────────────
  //  Statistics
  // ─────────────────────
  function loadStatistics() {
    chrome.runtime.sendMessage(
      { action: "getAllPhishingStatistics" },
      (stats) => {
        if (!stats) return;

        animateCounter(
          document.getElementById("total-count"),
          stats.totalPhishingAttempts || 0,
        );

        // Category bars
        const catEl = document.getElementById("category-statistics");
        const cc = stats.categoryCounts || {};
        const maxC = Math.max(...Object.values(cc), 1);
        const sorted = Object.entries(cc)
          .filter(([k]) => k !== "unknown")
          .sort((a, b) => b[1] - a[1]);

        let ch = "";
        sorted.forEach(([cat, n]) => {
          ch += `<div class="bar-row">
          <span class="bar-name">${icons[cat] || "🌐"} ${cat}</span>
          <div class="bar-track"><div class="bar-fill" style="width:0%" data-w="${(n / maxC) * 100}%"></div></div>
          <span class="bar-val">${n}</span>
        </div>`;
        });
        catEl.innerHTML = ch;
        requestAnimationFrame(() =>
          catEl
            .querySelectorAll(".bar-fill")
            .forEach((b) => (b.style.width = b.dataset.w)),
        );

        // Domain bars
        const dEl = document.getElementById("domain-statistics");
        const dc = stats.domainCounts || {};
        const ds = Object.entries(dc)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 6);
        const dMax = ds.length ? ds[0][1] : 1;

        let dh = "";
        if (!ds.length) {
          dh =
            '<div class="empty-state"><p style="font-size:12px">No data yet</p></div>';
        } else {
          ds.forEach(([dom, n]) => {
            const short = dom.length > 14 ? dom.substring(0, 14) + "…" : dom;
            dh += `<div class="bar-row">
            <span class="bar-name" title="${dom}">${short}</span>
            <div class="bar-track"><div class="bar-fill danger-bar" style="width:0%" data-w="${(n / dMax) * 100}%"></div></div>
            <span class="bar-val">${n}</span>
          </div>`;
          });
        }
        dEl.innerHTML = dh;
        requestAnimationFrame(() =>
          dEl
            .querySelectorAll(".bar-fill")
            .forEach((b) => (b.style.width = b.dataset.w)),
        );

        const mtBox = document.getElementById("most-targeted-section");
        const mtLbl = document.getElementById("most-targeted-category");
        if (stats.mostTargetedCategory && stats.mostTargetedCategory[1] > 0) {
          mtBox.style.display = "block";
          mtLbl.textContent =
            (icons[stats.mostTargetedCategory[0]] || "🌐") +
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
    const t0 = performance.now(),
      start = parseInt(el.textContent) || 0;
    (function step(t) {
      const p = Math.min((t - t0) / 600, 1);
      el.textContent = Math.round(
        start + (target - start) * (1 - Math.pow(1 - p, 3)),
      );
      if (p < 1) requestAnimationFrame(step);
    })(t0);
  }

  // ── Init ──
  loadSettings();
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith("http"))
      document.getElementById("url-input").value = tabs[0].url;
  });
});
