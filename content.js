// Content script for Phishing URL Detector

// Create and append warning overlay to the page
function createWarningOverlay(result) {
  removeWarningOverlay();

  const overlay = document.createElement("div");
  overlay.id = "phishing-detector-warning";
  overlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(10, 10, 20, 0.92);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      z-index: 2147483647;
      display: flex;
      justify-content: center;
      align-items: center;
      font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
      animation: overlayFadeIn 0.3s ease;
    `;

  const style = document.createElement("style");
  style.textContent = `
      @keyframes overlayFadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      @keyframes cardSlideIn {
        from { opacity: 0; transform: translateY(20px) scale(0.96); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }
      @keyframes pulseRing {
        0%, 100% { box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.4); }
        50% { box-shadow: 0 0 0 12px rgba(255, 71, 87, 0); }
      }
    `;
  overlay.appendChild(style);

  const content = document.createElement("div");
  content.style.cssText = `
      background: linear-gradient(145deg, rgba(26, 26, 46, 0.98), rgba(18, 18, 31, 0.98));
      border: 1px solid rgba(255, 71, 87, 0.2);
      border-radius: 16px;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5), 0 0 40px rgba(255, 71, 87, 0.1);
      width: 90%;
      max-width: 520px;
      padding: 36px;
      text-align: center;
      animation: cardSlideIn 0.4s ease 0.1s both;
    `;

  // Warning icon with pulse
  content.innerHTML = `
      <div style="
        width: 72px; height: 72px; margin: 0 auto 20px;
        background: rgba(255, 71, 87, 0.12);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 36px;
        animation: pulseRing 2s ease-in-out infinite;
      ">⚠️</div>
      <h1 style="
        color: #ff4757;
        font-size: 22px;
        font-weight: 700;
        margin-bottom: 8px;
        letter-spacing: -0.3px;
      ">Phishing Threat Detected</h1>
      <p style="
        color: #8b8ba3;
        font-size: 14px;
        margin-bottom: 24px;
        line-height: 1.5;
      ">
        This website has been flagged as a potential phishing site with
        <strong style="color: #ff4757;">${(result.confidence * 100).toFixed(1)}%</strong> confidence.
      </p>
    `;

  // Domain info card
  if (result.urlInfo && result.urlInfo.domain) {
    const infoCard = document.createElement("div");
    infoCard.style.cssText = `
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.06);
        padding: 16px;
        border-radius: 10px;
        margin-bottom: 24px;
        text-align: left;
      `;

    let infoHtml = `
        <p style="margin: 6px 0; color: #e8e8f0; font-size: 13px;">
          🌐 Domain: <strong>${result.urlInfo.domain}</strong>
        </p>`;

    if (result.domainAge) {
      infoHtml += `
          <p style="margin: 6px 0; color: #8b8ba3; font-size: 13px;">
            📅 Domain Age: <strong style="color: ${result.domainAge.isSuspicious ? "#ff4757" : "#e8e8f0"};">
            ${result.domainAge.ageInDays} days</strong>
            (Registered: ${result.domainAge.registrationDate})
          </p>`;
    }

    if (result.phishingCount && result.phishingCount > 0) {
      infoHtml += `
          <p style="margin: 6px 0; color: #ff4757; font-size: 13px;">
            🚫 <strong>${result.phishingCount} phishing attempts</strong> from this domain.
          </p>`;
    }

    infoCard.innerHTML = infoHtml;
    content.appendChild(infoCard);
  }

  // Buttons
  const buttons = document.createElement("div");
  buttons.style.cssText = `
      display: flex;
      justify-content: center;
      gap: 12px;
    `;

  const backButton = document.createElement("button");
  backButton.innerText = "← Back to Safety";
  backButton.style.cssText = `
      background: linear-gradient(135deg, #00d4ff, #0099cc);
      color: #000;
      border: none;
      padding: 12px 28px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      font-family: inherit;
      box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
      transition: all 0.2s;
    `;
  backButton.addEventListener("mouseenter", () => {
    backButton.style.boxShadow = "0 6px 25px rgba(0, 212, 255, 0.5)";
    backButton.style.transform = "translateY(-1px)";
  });
  backButton.addEventListener("mouseleave", () => {
    backButton.style.boxShadow = "0 4px 15px rgba(0, 212, 255, 0.3)";
    backButton.style.transform = "translateY(0)";
  });
  backButton.addEventListener("click", () => history.back());

  const proceedButton = document.createElement("button");
  proceedButton.innerText = "Proceed Anyway";
  proceedButton.style.cssText = `
      background: transparent;
      color: #5a5a72;
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 12px 28px;
      border-radius: 8px;
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.2s;
    `;
  proceedButton.addEventListener("mouseenter", () => {
    proceedButton.style.borderColor = "rgba(255, 255, 255, 0.2)";
    proceedButton.style.color = "#8b8ba3";
  });
  proceedButton.addEventListener("mouseleave", () => {
    proceedButton.style.borderColor = "rgba(255, 255, 255, 0.1)";
    proceedButton.style.color = "#5a5a72";
  });
  proceedButton.addEventListener("click", () => removeWarningOverlay());

  buttons.appendChild(backButton);
  buttons.appendChild(proceedButton);
  content.appendChild(buttons);
  overlay.appendChild(content);
  document.body.appendChild(overlay);
}

function removeWarningOverlay() {
  const existingOverlay = document.getElementById("phishing-detector-warning");
  if (existingOverlay) {
    existingOverlay.remove();
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showWarning") {
    createWarningOverlay(message.data);
    sendResponse({ success: true });
  }
});

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initializeContentScript);
} else {
  initializeContentScript();
}

function initializeContentScript() {
  console.log("Phishing URL Detector content script initialized");
}
