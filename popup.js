document.addEventListener("DOMContentLoaded", function () {
  // ── Theme ──
  const themeBtn = document.getElementById("theme-toggle");
  const root = document.documentElement;

  chrome.storage.local.get("theme", (d) => {
    const t = d.theme || "light";
    root.setAttribute("data-theme", t);
    themeBtn.textContent = t === "dark" ? "☀️" : "🌙";
  });

  themeBtn.addEventListener("click", () => {
    const next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    themeBtn.textContent = next === "dark" ? "☀️" : "🌙";
    chrome.storage.local.set({ theme: next });
  });

  // ── Tabs ──
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const t = btn.dataset.tab;
      document
        .querySelectorAll(".tab-btn")
        .forEach((b) => b.classList.remove("active"));
      document
        .querySelectorAll(".tab-content")
        .forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(t).classList.add("active");
      if (t === "history") loadHistory();
      if (t === "settings") loadSettings();
      if (t === "statistics") loadStats();
    });
  });

  // ── Sensitivity ──
  const slider = document.getElementById("sensitivity-level");
  const sliderVal = document.getElementById("sensitivity-display");

  function updateSliderFill() {
    sliderVal.textContent = slider.value;
    const pct = ((slider.value - 1) / 4) * 100;
    slider.style.setProperty("--val", pct + "%");
  }

  slider.addEventListener("input", updateSliderFill);

  // ── Actions ──
  document.getElementById("analyze-btn").addEventListener("click", () => {
    const u = document.getElementById("url-input").value.trim();
    if (u) {
      loading(true);
      analyze(u);
    }
  });

  document.getElementById("url-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const u = e.target.value.trim();
      if (u) {
        loading(true);
        analyze(u);
      }
    }
  });

  document
    .getElementById("analyze-current-btn")
    .addEventListener("click", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs?.[0]?.url) {
          document.getElementById("url-input").value = tabs[0].url;
          loading(true);
          analyze(tabs[0].url);
        }
      });
    });

  document
    .querySelectorAll('#settings input[type="checkbox"]')
    .forEach((c) => c.addEventListener("change", saveSettings));
  slider.addEventListener("change", saveSettings);

  document
    .getElementById("clear-history")
    .addEventListener("click", () =>
      chrome.runtime.sendMessage({ action: "clearDetections" }, () =>
        loadHistory(),
      ),
    );
  document.getElementById("refresh-stats").addEventListener("click", loadStats);

  // ──────────────────
  //  Core
  // ──────────────────

  function loading(on) {
    document.getElementById("loading").classList.toggle("active", on);
    if (on) document.getElementById("result").classList.remove("active");
  }

  function analyze(url) {
    if (!/^https?:\/\//i.test(url)) url = "http://" + url;
    chrome.runtime.sendMessage(
      { action: "analyzeUrl", url, checkDomainAge: true },
      (r) => {
        loading(false);
        if (r) showResult(r);
      },
    );
  }

  const ico = {
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

  function showResult(r) {
    const el = document.getElementById("result");
    const bad = r.classification === "Phishing";
    const pct = (r.confidence * 100).toFixed(1);
    const cat = r.category || r.urlInfo?.category || "unknown";
    const dom = r.urlInfo?.domain || r.url;

    const risks = [];
    if (r.urlInfo) {
      if (r.urlInfo.hasSuspiciousWords)
        risks.push("Suspicious keywords detected");
      if (r.urlInfo.hasIpAddress)
        risks.push("IP address used instead of domain");
      if (r.urlInfo.domainLength > 30) risks.push("Unusually long domain");
      if (r.urlInfo.numDots > 3) risks.push("Excessive dots in URL");
      if (r.urlInfo.numHyphens > 2) risks.push("Multiple hyphens in domain");
      if (r.urlInfo.numAtSymbols > 0) risks.push("Contains @ symbol");
      if (r.urlInfo.subdomainLevels > 2) risks.push("Deep subdomain nesting");
    }
    if (r.domainAge?.isSuspicious)
      risks.push("New domain (" + r.domainAge.ageInDays + " days)");
    if (r.phishingCount > 1) risks.push(r.phishingCount + " prior attempts");

    let h = `<div class="card">
      <div class="res-top">
        <div class="res-icon ${bad ? "bad" : "ok"}">${bad ? "⚠️" : "✓"}</div>
        <div><div class="res-title">${bad ? "Threat Detected" : "URL is Safe"}</div><div class="res-domain">${dom}</div></div>
      </div>
      <div class="prog-header">
        <span class="prog-label">Confidence</span>
        <span class="prog-val" style="color:${bad ? "var(--danger)" : "var(--success)"}">${pct}%</span>
      </div>
      <div class="prog-track"><div class="prog-fill ${bad ? "fill-bad" : "fill-ok"}" id="conf-bar"></div></div>
      <div class="tags-row">
        <span class="tag ${bad ? "tag-red" : "tag-green"}">${bad ? "Phishing" : "Legitimate"}</span>
        <span class="tag tag-blue">${ico[cat] || "🌐"} ${cat}</span>
      </div>`;

    if (r.domainAge) {
      h += `<div class="age-bar"><span>Age: <strong>${r.domainAge.ageInDays} days</strong></span><span>Reg: <strong>${r.domainAge.registrationDate}</strong></span></div>`;
    }

    if (risks.length) {
      h +=
        '<div class="info-section"><div class="info-label">Risk Factors</div>';
      risks.forEach(
        (f) =>
          (h += `<div class="info-row"><span class="i-dot red"></span>${f}</div>`),
      );
      h += "</div>";
    } else if (!bad) {
      h += `<div class="info-section"><div class="info-label">Analysis</div>
        <div class="info-row"><span class="i-dot green"></span>No suspicious patterns</div>
        <div class="info-row"><span class="i-dot green"></span>Normal domain structure</div></div>`;
    }

    h += "</div>";
    el.innerHTML = h;
    el.classList.add("active");
    requestAnimationFrame(() => {
      const bar = document.getElementById("conf-bar");
      if (bar) bar.style.width = pct + "%";
    });
  }

  // ──────────────────
  //  History
  // ──────────────────
  function loadHistory() {
    chrome.runtime.sendMessage({ action: "getDetections" }, (list) => {
      const el = document.getElementById("detections-list");
      if (!list?.length) {
        el.innerHTML = '<div class="empty">No detections yet</div>';
        return;
      }
      el.innerHTML = list
        .slice(0, 50)
        .map((d) => {
          const bad = d.classification === "Phishing";
          const c = d.confidence ? (d.confidence * 100).toFixed(1) + "%" : "";
          return `<div class="det-item">
          <div class="det-url">${d.url}</div>
          <div class="det-meta">
            <span class="tag ${bad ? "tag-red" : "tag-green"}">${bad ? "Phishing" : "Safe"} ${c}</span>
            <span class="tag tag-blue">${ico[d.category || "unknown"] || "🌐"} ${d.category || "unknown"}</span>
            <span class="det-time">${new Date(d.timestamp).toLocaleString()}</span>
          </div>
        </div>`;
        })
        .join("");
    });
  }

  // ──────────────────
  //  Settings
  // ──────────────────
  function loadSettings() {
    chrome.storage.local.get("settings", (d) => {
      if (!d.settings) return;
      const s = d.settings;
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
        updateSliderFill();
      } else {
        updateSliderFill();
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

  // ──────────────────
  //  Stats
  // ──────────────────
  function loadStats() {
    chrome.runtime.sendMessage({ action: "getAllPhishingStatistics" }, (s) => {
      if (!s) return;
      counterAnim(
        document.getElementById("total-count"),
        s.totalPhishingAttempts || 0,
      );

      const cc = s.categoryCounts || {};
      const mx = Math.max(...Object.values(cc), 1);
      const catEl = document.getElementById("category-statistics");
      catEl.innerHTML = Object.entries(cc)
        .filter(([k]) => k !== "unknown")
        .sort((a, b) => b[1] - a[1])
        .map(
          ([k, v]) =>
            `<div class="bar-row"><span class="bar-name">${ico[k] || "🌐"} ${k}</span><div class="bar-track"><div class="bar-fill" style="width:0%" data-w="${(v / mx) * 100}%"></div></div><span class="bar-val">${v}</span></div>`,
        )
        .join("");
      raf(catEl);

      const dc = s.domainCounts || {};
      const ds = Object.entries(dc)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6);
      const dm = ds[0]?.[1] || 1;
      const dEl = document.getElementById("domain-statistics");
      dEl.innerHTML = ds.length
        ? ds
            .map(([k, v]) => {
              const n = k.length > 14 ? k.slice(0, 14) + "…" : k;
              return `<div class="bar-row"><span class="bar-name" title="${k}">${n}</span><div class="bar-track"><div class="bar-fill red" style="width:0%" data-w="${(v / dm) * 100}%"></div></div><span class="bar-val">${v}</span></div>`;
            })
            .join("")
        : '<div class="empty">No data</div>';
      raf(dEl);

      const mt = document.getElementById("most-targeted-section");
      if (s.mostTargetedCategory?.[1] > 0) {
        mt.style.display = "block";
        document.getElementById("most-targeted-category").textContent =
          (ico[s.mostTargetedCategory[0]] || "🌐") +
          " " +
          s.mostTargetedCategory[0] +
          " (" +
          s.mostTargetedCategory[1] +
          ")";
      } else mt.style.display = "none";
    });
  }

  function raf(el) {
    requestAnimationFrame(() =>
      el
        .querySelectorAll(".bar-fill")
        .forEach((b) => (b.style.width = b.dataset.w)),
    );
  }

  function counterAnim(el, to) {
    const t0 = performance.now(),
      from = +el.textContent || 0;
    (function f(t) {
      const p = Math.min((t - t0) / 500, 1);
      el.textContent = Math.round(
        from + (to - from) * (1 - Math.pow(1 - p, 3)),
      );
      if (p < 1) requestAnimationFrame(f);
    })(t0);
  }

  // Init
  loadSettings();
  chrome.tabs.query({ active: true, currentWindow: true }, (t) => {
    if (t?.[0]?.url?.startsWith("http"))
      document.getElementById("url-input").value = t[0].url;
  });
});
