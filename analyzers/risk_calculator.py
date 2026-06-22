def calculate_score(
    ml_probability,
    url_rule_score,
    domain_score,
    ssl_score,
    redirect_score,
    content_score,
    typo_score,
    password_fields,
    ssl_valid,
    google_status=None
):
    # Combine rule-based scores
    total_rule_score = (
        url_rule_score
        + domain_score
        + ssl_score
        + redirect_score
        + content_score
    )

    total_rule_score = min(total_rule_score, 100)

    # Base final score
    final_score = (
        total_rule_score * 0.60
        + ml_probability * 0.40
    )

   
    if password_fields > 0:
        final_score += 10

    # ✅ Google Safe Browsing impact (added, not replacing logic)
    if google_status == "Malicious":
        final_score += 40 # strong penalty
    elif google_status == "Safe":
        final_score += 0 # slight trust boost
	
    # Final normalization
    final_score = round(min(max(final_score, 0), 100))

    # Verdict
    if final_score >= 55:
        verdict = "Phishing"
    elif final_score >= 35: #30:
        verdict = "Suspicious / Information Not Found"
    else:
        verdict = "Legitimate"

    return final_score, total_rule_score, verdict
