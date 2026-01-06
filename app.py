from flask import Flask, render_template, request
import pickle
import os
from urllib.parse import urlparse
import idna

app = Flask(__name__)

# =========================
# Load trained model
# =========================
MODEL_PATH = "model.pkl"

if not os.path.exists(MODEL_PATH) or os.path.getsize(MODEL_PATH) == 0:
    raise ValueError("model.pkl missing or empty. Train model first.")

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# =========================
# Threat Intelligence Lists
# =========================
TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "github.com",
    "microsoft.com", "amazon.com", "linkedin.com"
]

SUSPICIOUS_HOSTING = [
    "trycloudflare.com",
    "github.io",
    "netlify.app",
    "vercel.app",
    "firebaseapp.com",
    "pages.dev"
]

LOGIN_KEYWORDS = [
    "/login", "/signin", "/verify", "/account",
    "/update", "/secure", "/auth"
]

BRAND_KEYWORDS = [
    "google", "youtube", "paypal", "facebook",
    "instagram", "microsoft", "amazon", "linkedin"
]

# Visual homograph tricks
VISUAL_SUBSTITUTIONS = {
    "rn": "m",
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "vv": "w"
}

# =========================
# Feature Simulation (ML)
# =========================
def url_to_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features = []
    features.append(-1 if any(c.isdigit() for c in domain) else 1)
    features.append(-1 if len(url) > 75 else 1)
    features.append(-1 if any(s in url for s in ["bit.ly", "tinyurl", "goo.gl"]) else 1)
    features.append(-1 if "@" in url else 1)
    features.append(-1 if url.count("//") > 1 else 1)
    features.append(-1 if "-" in domain else 1)
    features.append(-1 if domain.count(".") > 2 else 1)
    features.append(1 if parsed.scheme == "https" else -1)

    while len(features) < 30:
        features.append(1)

    return features

# =========================
# Homograph / Lookalike Detection
# =========================
def detect_homograph(domain):
    reasons = []

    # Unicode / IDN detection
    try:
        ascii_domain = idna.encode(domain).decode("ascii")
        if ascii_domain.startswith("xn--"):
            reasons.append("Unicode (IDN) homograph domain detected")
    except:
        pass

    # Visual substitution (rn → m, etc.)
    for fake, real in VISUAL_SUBSTITUTIONS.items():
        if fake in domain:
            reasons.append(f"Visual impersonation detected: '{fake}' looks like '{real}'")

    # Brand impersonation
    for brand in BRAND_KEYWORDS:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            reasons.append(f"Possible impersonation of {brand}")

    return reasons

# =========================
# Explanation Generator
# =========================
def explain_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    reasons = []

    if parsed.scheme == "http":
        reasons.append("Uses insecure HTTP protocol")

    if any(host in domain for host in SUSPICIOUS_HOSTING):
        reasons.append("Hosted on free or temporary infrastructure")

    if any(k in path for k in LOGIN_KEYWORDS):
        reasons.append("Login or credential collection page detected")

    if "-" in domain:
        reasons.append("Suspicious hyphenated domain")

    if domain.count(".") > 2:
        reasons.append("Too many subdomains")

    reasons.extend(detect_homograph(domain))
    return reasons

# =========================
# Flask Route
# =========================
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk = None
    confidence = None
    reasons = []

    if request.method == "POST":
        url = request.form.get("url")
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        # 1️⃣ Trusted domains
        if any(td == domain or domain.endswith("." + td) for td in TRUSTED_DOMAINS):
            result = "✅ LEGITIMATE URL"
            risk = "Low Risk"
            confidence = 95
            reasons = ["Well-known trusted domain"]

        # 2️⃣ Homograph / lookalike phishing (rnicrosoft, goog1e)
        else:
            homograph_reasons = detect_homograph(domain)
            if homograph_reasons:
                result = "🚨 PHISHING URL"
                risk = "High Risk"
                confidence = 95
                reasons = homograph_reasons

            # 3️⃣ Suspicious hosting + login page
            elif any(host in domain for host in SUSPICIOUS_HOSTING) and any(k in path for k in LOGIN_KEYWORDS):
                result = "🚨 PHISHING URL"
                risk = "High Risk"
                confidence = 95
                reasons = explain_url(url)

            # 4️⃣ HTTP login pages
            elif parsed.scheme == "http" and any(k in path for k in LOGIN_KEYWORDS):
                result = "🚨 PHISHING URL"
                risk = "High Risk"
                confidence = 90
                reasons = explain_url(url)

            # 5️⃣ ML fallback
            else:
                features = url_to_features(url)
                prob = model.predict_proba([features])[0][1]
                confidence = int(prob * 100)

                if prob > 0.7:
                    result = "🚨 PHISHING URL"
                    risk = "High Risk"
                elif prob > 0.4:
                    result = "⚠️ SUSPICIOUS URL"
                    risk = "Medium Risk"
                else:
                    result = "✅ LEGITIMATE URL"
                    risk = "Low Risk"

                reasons = explain_url(url)

    return render_template(
        "index.html",
        result=result,
        risk=risk,
        confidence=confidence,
        reasons=reasons
    )

# =========================
# Run App
# =========================
if __name__ == "__main__":
    app.run(debug=True)
