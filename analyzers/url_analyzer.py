import re

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "signin",
    "password", "confirm", "bank", "wallet", "update",
    "billing", "otp", "support", "payment", "alert"
]


def analyze_url(url, domain):
    score = 0
    reasons = []

    if len(url) > 80:
        score += 10
        reasons.append("Very long URL")

    if domain.count(".") > 3:
        score += 10
        reasons.append("Too many subdomains")

    if "-" in domain:
        score += 10
        reasons.append("Hyphenated domain")

    if "@" in url:
        score += 20
        reasons.append("@ symbol inside URL")

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 30
        reasons.append("Raw IP address used")

    found = [word for word in SUSPICIOUS_WORDS if word in url.lower()]

    if found:
        keyword_score = min(20, len(found) * 5)
        score += keyword_score
        reasons.append("Suspicious keywords found: " + ", ".join(found))

    return score, reasons
