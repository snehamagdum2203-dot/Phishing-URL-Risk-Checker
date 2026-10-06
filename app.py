from ipaddress import ip_address
from urllib.parse import urlsplit

from flask import Flask, jsonify, request

app = Flask(__name__)

SUSPICIOUS_WORDS = {
    "account", "confirm", "login", "password", "secure",
    "signin", "update", "verify", "wallet",
}


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/api/v1/check")
def check_url():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json."}), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "'url' must be a non-empty string."}), 400

    url = url.strip()
    if len(url) > 2048:
        return jsonify({"error": "URL must be 2048 characters or fewer."}), 400

    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        # Accessing .port also checks whether the port is valid.
        _ = parts.port
    except ValueError:
        return jsonify({"error": "URL format is invalid."}), 400

    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        return jsonify({
            "error": "URL must include http:// or https:// and a valid hostname."
        }), 400

    score = 0
    reasons = []

    def add_risk(points, reason):
        nonlocal score
        score += points
        reasons.append(reason)

    if parts.scheme.lower() == "http":
        add_risk(20, "The URL does not use HTTPS.")

    if "@" in parts.netloc:
        add_risk(20, "The URL contains @ in its network location.")

    try:
        ip_address(hostname)
        add_risk(30, "The hostname is an IP address instead of a domain name.")
    except ValueError:
        pass

    hostname_parts = hostname.lower().split(".")
    if len(hostname_parts) > 4:
        add_risk(15, "The hostname has an unusually large number of subdomains.")

    if any(word in url.lower() for word in SUSPICIOUS_WORDS):
        add_risk(15, "The URL contains words often used in account-related links.")

    if len(url) > 150:
        add_risk(10, "The URL is unusually long.")

    score = min(score, 100)
    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return jsonify({
        "checked_url": url,
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "note": "This is a basic rule-based estimate, not a guarantee of safety.",
    }), 200


if __name__ == "__main__":
    app.run(debug=True)