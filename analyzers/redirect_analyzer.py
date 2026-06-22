from urllib.parse import urlparse


def score_redirects(crawl_data, original_domain):
    score = 0
    reasons = []

    if crawl_data["redirects"] >= 2:
        score += 10
        reasons.append("Multiple redirects detected")

    if crawl_data["redirects"] >= 3:
        score += 15
        reasons.append("Long redirect chain")

    final_domain = urlparse(crawl_data["final_url"]).netloc.replace("www.", "")

    if final_domain and final_domain != original_domain:
        score += 15
        reasons.append("Redirects to a different domain")

    if crawl_data["password_fields"] > 0:
        score += 10
        reasons.append("Password field detected")

    if crawl_data["external_links"] > 20:
        score += 10
        reasons.append("Large number of external links")

    return score, reasons
