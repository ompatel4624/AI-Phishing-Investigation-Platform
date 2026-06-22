import ssl
import socket
from datetime import datetime

def format_issuer(issuer_tuple):
    try:
        issuer_dict = {}

        for item in issuer_tuple:
            for key, value in item:
                issuer_dict[key] = value

        return {
            "organization": issuer_dict.get("organizationName", ""),
            "common_name": issuer_dict.get("commonName", ""),
            "country": issuer_dict.get("countryName", "")
        }
            
    except:
        return "Unknown"

def _get_ssl_info(domain):
    context = ssl.create_default_context()

    with socket.create_connection((domain, 443), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()

    issuer_info = format_issuer(cert.get("issuer", []))

    issued_on = cert.get("notBefore")
    expires_on = cert.get("notAfter")

    from datetime import datetime

    issued_date = datetime.strptime(issued_on, "%b %d %H:%M:%S %Y %Z") if issued_on else None
    expiry_date = datetime.strptime(expires_on, "%b %d %H:%M:%S %Y %Z") if expires_on else None

    days_left = (expiry_date - datetime.utcnow()).days if expiry_date else None

    return {
        "valid": True,
        "issuer": issuer_info,
        "issued_on": issued_date.strftime("%Y-%m-%d") if issued_date else "Unknown",
        "expires_on": expiry_date.strftime("%Y-%m-%d") if expiry_date else "Unknown",
        "days_left": days_left
    }

def check_ssl(domain):
    try:
        return _get_ssl_info(domain)
    except:
        try:
            # 🔁 fallback to www version
            return _get_ssl_info("www." + domain)
        except:
            return {
                "valid": False,
                "issuer": {
                    "organization": "Unavailable",
                    "common_name": "Unavailable",
                    "country": "Unavailable"
                },
                "issued_on": "Unavailable",
                "expires_on": "Unavailable",
                "days_left": None
            }

def score_ssl(data):
    if not data["valid"]:
        return 15, ["Invalid or missing SSL certificate"]
        
    # Warning if SSL is about to expire
    if data["days_left"] is not None and data["days_left"] < 10:
        return 5, ["SSL certificate is about to expire"]

    return 0, []
