# Phishing URL Detector 🛡️

A highly advanced, completely serverless, and privacy-first Chrome Extension designed to detect zero-day phishing websites locally in your browser. Utilizing a native **Logistic Regression Machine Learning pipeline** combined with **Live Structural DOM Intelligence**, it catches malicious domains without sacrificing your privacy or relying on third-party tracking APIs.

> **100% Privacy by Design**: Unlike legacy detectors, this engine strips out Google Safe Browsing and remote telemetry APIs entirely. Your browsing activity never leaves your machine.

---

## 🚀 Key Features

- 🤖 **Native Logic Regression ML Model**  
   Replaces arbitrary heuristic guessing with true localized predictive modeling. Features are dynamically normalized into a 13-point extraction vector (e.g., String Length, Entropy Bounds, Credential Tensors), fed through a pre-calculated mathematical weight matrix, and outputted via a Sigmoid Activation function for hyper-accurate threat probabilities.

- 🕷️ **Live Structural DOM Extraction**  
   Automatically catches 10+ year old compromised domains that look "legitimate" on paper. Operates a silent, high-speed (1.2-second timeout) structural HTML scanner in the background to detect hidden iframe harvesters, mismatched cross-origin form endpoints, and unexpected `<input type="password">` boxes nested deep inside generic domains.

- 🌐 **Serverless RDAP Telemetry**  
   Performs lightning-fast WHOIS Domain-Age checks solely relying on standardized ICANN RDAP endpoints. Instantly flags burner domains and freshly registered sites masquerading as legacy bank URLs.

- 🎨 **Premium UI/UX Design**  
   Engineered with a sleek, Linear-inspired Glassmorphism aesthetic. Features an interactive dashboard covering real-time scanning, comprehensive historical detection analytics, categorized visual data rendering, and dark/light mode persistent themes.

---

## 🛠️ Installation (Developer Mode)

1. Clone or download this repository to your local machine.
2. Open Google Chrome or Brave and navigate to the extensions page: `chrome://extensions/`
3. Enable **Developer mode** via the toggle switch in the top right corner.
4. Click on the **Load unpacked** button.
5. Select the main directory folder containing the `manifest.json`.
6. The Phishing URL Detector icon will now appear in your browser's extension toolbar!

---

## ⚙️ How It Works (Under the Hood)

1. **Feature Extraction**: When you click Analyze, the Service Worker extracts hard character sets (Entropy, Hyphens, Length, '@' inclusions).
2. **Context Crawling**: The Worker secretly spins up an `AbortController` fetch layer, dragging the target site's raw HTML structure into an isolation sandbox to scan for structural credential threats.
3. **Logistics**: The gathered data builds a `[Z]` matrix against pre-expert weights (`W`).
4. **Calculus Application**: `Probability = 1 / (1 + e^-Z)`. Any final probabilistic score that passes the normalized sensitivity threshold flags a visual red alert on the UI dashboard in 0.05 seconds.

---

## 👤 Author

Developed by **Anish Pawar**  
📧 Email: [anishp1210@gmail.com](mailto:anishp1210@gmail.com)

_Built securely for Manifest V3 ecosystems._
