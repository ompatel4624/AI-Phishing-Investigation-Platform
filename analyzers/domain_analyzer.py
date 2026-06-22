import socket
import ssl
import whois
import requests
from datetime import datetime


def get_domain_info(domain):
    info = {
        "ip": "Unavailable",
        "registrar": "Unavailable",
        "age_years": None,
        "exists": False,
        "reachable": False,
        "hosting_reason": "Unknown"
    }

    # 1. Resolve domain
    try:
        info["ip"] = socket.gethostbyname(domain)
        info["exists"] = True
    except Exception:
        info["hosting_reason"] = "Domain does not resolve"
        return info

    # 2. WHOIS lookup
    try:
        data = whois.whois(domain)

        if data.registrar:
            info["registrar"] = str(data.registrar)

        creation = data.creation_date

        # WHOIS can return a list instead of a single date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            info["age_years"] = round(
                (datetime.now() - creation).days / 365,
                2
            )

    except Exception:
        pass

    # 3. RDAP fallback if age still missing
    if info["age_years"] is None:
        try:
            response = requests.get(
                f"https://rdap.org/domain/{domain}",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        created = event.get("eventDate")

                        if created:
                            created_dt = datetime.fromisoformat(
                                created.replace("Z", "+00:00")
                            )

                            info["age_years"] = round(
                                (
                                    datetime.now(created_dt.tzinfo)
                                    - created_dt
                                ).days / 365,
                                2
                            )
                            break

        except Exception:
            pass

    # 4. WhoisXML final fallback
    if info["age_years"] is None:
        try:
            response = requests.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON",
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()

                created = (
                    data.get("WhoisRecord", {})
                    .get("createdDate")
                )

                if created:
                    try:
                        created_dt = datetime.fromisoformat(
                            created.replace("Z", "+00:00")
                        )
                    except Exception:
                        created_dt = datetime.strptime(
                            created[:10],
                            "%Y-%m-%d"
                        )

                    info["age_years"] = round(
                        (
                            datetime.now(created_dt.tzinfo)
                            - created_dt
                        ).days / 365,
                        2
                    )

        except Exception:
            pass

    # 5. Better hosting / reachability detection
    # Try HTTPS first, then HTTP
    try:
        sock = socket.create_connection((domain, 443), timeout=5)

        # Perform SSL handshake to confirm HTTPS server
        context = ssl.create_default_context()
        secure_sock = context.wrap_socket(
            sock,
            server_hostname=domain
        )
        secure_sock.close()

        info["reachable"] = True
        info["hosting_reason"] = "HTTPS server detected"

    except Exception:
        try:
            sock = socket.create_connection((domain, 80), timeout=5)
            sock.close()

            info["reachable"] = True
            info["hosting_reason"] = "HTTP server detected"

        except Exception:
            info["reachable"] = False
            info["hosting_reason"] = (
                "Domain exists but no web server detected"
            )

    return info


def score_domain(info):
    score = 0
    reasons = []

    # Domain does not exist
    if not info.get("exists", True):
        reasons.append("Domain does not exist")
        return score, reasons

    # Domain exists but no server
    if info.get("exists") and not info.get("reachable"):
        score += 25
        reasons.append(info.get("hosting_reason"))

    # Domain age
    if info["age_years"] is None:
        score += 3
        reasons.append("Domain age unavailable")

    elif info["age_years"] < 0.5:
        score += 15
        reasons.append(
            f"Very new domain ({info['age_years']} years old)"
        )

    elif info["age_years"] < 2:
        score += 5
        reasons.append(
            f"Young domain ({info['age_years']} years old)"
        )

    # IP unavailable
    if info["ip"] == "Unavailable":
        score += 5
        reasons.append("Unable to resolve domain IP address")

    return score, reasons
