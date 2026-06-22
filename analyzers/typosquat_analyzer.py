from difflib import SequenceMatcher

KNOWN_BRANDS = [
    "google", "paypal", "microsoft", "amazon", "apple",
    "facebook", "instagram", "netflix", "bankofamerica",
    "outlook", "icloud", "steam", "discord"
]


def check_typosquat(domain):
    score = 0
    reasons = []

    domain = domain.lower().replace("www.", "")
    parts = domain.split(".")

    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    root = registered_domain.split(".")[0]

    transformed = (
        root.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
    )

    for brand in KNOWN_BRANDS:
        if brand in parts[:-2]:
            score += 35
            reasons.append(f"Brand name '{brand}' used as deceptive subdomain")

        similarity = max(
            SequenceMatcher(None, root, brand).ratio(),
            SequenceMatcher(None, transformed, brand).ratio()
        )

        if similarity >= 0.78 and root != brand:
            score += 40
            reasons.append(f"Possible typosquatting of {brand}")

    return min(score, 50), reasons
