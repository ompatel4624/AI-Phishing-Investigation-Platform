# app.py

from urllib.parse import urlparse
import joblib
from flask import Flask, render_template, request

from analyzers.url_analyzer import analyze_url
from analyzers.typosquat_analyzer import check_typosquat
from analyzers.domain_analyzer import get_domain_info, score_domain
from analyzers.ssl_analyzer import check_ssl, score_ssl
from analyzers.content_rules import analyze_page_text
from analyzers.crawler import crawl_site
from analyzers.redirect_analyzer import score_redirects
from analyzers.risk_calculator import calculate_score
from analyzers.threat_intel import check_google_safe_browsing

app = Flask(__name__)

# Load trained machine learning model
model = joblib.load("training/trained_url_model.pkl")


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    threat_result = None 

    if request.method == "POST":
        url = request.form["url"].strip()

        # Add https if user enters only domain
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            
        threat_result = check_google_safe_browsing(url)

        # Extract clean domain
        domain = urlparse(url).netloc.replace("www.", "")

        # URL Rule Analysis
        url_rule_score, reasons = analyze_url(url, domain)

        # Typosquatting Analysis
        typo_score, typo_reasons = check_typosquat(domain)
        url_rule_score += typo_score
        reasons.extend(typo_reasons)

        # Machine Learning Model
        ml_probability = model.predict_proba([url])[0][1] * 100

        # Domain Analysis
        domain_info = get_domain_info(domain)
        domain_score, domain_reasons = score_domain(domain_info)
        reasons.extend(domain_reasons)

        # SSL Analysis
        ssl_info = check_ssl(domain)
        ssl_score, ssl_reasons = score_ssl(ssl_info)
        reasons.extend(ssl_reasons)

        # Crawl Website
        crawl_data = crawl_site(url)

        # Redirect Analysis
        redirect_score, redirect_reasons = score_redirects(crawl_data, domain)
        reasons.extend(redirect_reasons)

        # Page Content Analysis
        content_score, content_reasons = analyze_page_text(crawl_data["text"])
        reasons.extend(content_reasons)

        # Risk Calculation moved to separate file
        final_score, total_rule_score, verdict = calculate_score(
            ml_probability=ml_probability,
            url_rule_score=url_rule_score,
            domain_score=domain_score,
            ssl_score=ssl_score,
            redirect_score=redirect_score,
            content_score=content_score,
            typo_score=typo_score,
            password_fields=crawl_data["password_fields"],
            ssl_valid=ssl_info["valid"],
            google_status=threat_result["status"]
        )

        # Add extra reasons shown in dashboard
        if crawl_data["password_fields"] > 0:
            reasons.append("Password field detected on webpage")

        if crawl_data["password_fields"] > 0 and typo_score >= 30:
            reasons.append("Typosquatting combined with password field")
        
                # Google Safe Browsing reasoning
        if threat_result and threat_result["status"] == "Malicious":
            reasons.append("Google Safe Browsing flagged this URL as malicious")
            
        # Dashboard Result
        result = {
            "score": final_score,
            "verdict": verdict,
            "reasons": reasons,
            "domain": domain_info,
            "ssl": ssl_info,
            "crawl": crawl_data,
            "ml_probability": round(ml_probability, 2),
            "total_rule_score": total_rule_score
        }

    return render_template(
    "index.html",
    result=result,
    threat_intel=threat_result
    )


if __name__ == "__main__":
    app.run(debug=True)
