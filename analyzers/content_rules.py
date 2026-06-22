SUSPICIOUS_TEXT = [
    "verify your account",
    "confirm your password",
    "account suspended",
    "login immediately",
    "bank account",
    "credit card",
    "wallet",
    "otp",
    "security alert",
    "verify now",
    "sign in",
    "update payment",
    "confirm identity"
]


def analyze_page_text(text):
    score = 0
    reasons = []

    lowered = text.lower()

    for phrase in SUSPICIOUS_TEXT:
        if phrase in lowered:
            score += 10
            reasons.append(f"Suspicious page text: {phrase}")

    return min(score, 30), reasons
