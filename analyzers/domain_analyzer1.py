import socket
import whois
import requests
from datetime import datetime


def get_domain_info(domain):
    info = {
        "ip": "Unavailable",
        "registrar": "Unavailable",
        "age_years": None
    }

    # Resolve IP address
    try:
        info["ip"] = socket.gethostbyname(domain)
    except Exception:
        pass

    # First attempt: WHOIS lookup
    try:
        data = whois.whois(domain)

        if data.registrar:
            info["registrar"] = str(data.registrar)

        creation = data.creation_date

        # WHOIS sometimes returns a list of dates
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            info["age_years"] = round(
                (datetime.now() - creation).days / 365,
                2
            )
            return info

    except Exception:
        pass

    # Backup attempt: RDAP lookup
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if "events" in data:
                for event in data["events"]:
                    if event.get("eventAction") == "registration":
                        created = event.get("eventDate")

                        if created:
                            created_dt = datetime.fromisoformat(
                                created.replace("Z", "+00:00")
                            )

                            info["age_years"] = round(
                                (datetime.now(created_dt.tzinfo) - created_dt).days / 365,
                                2
                            )

                            return info

    except Exception:
        pass

    # Final fallback: WhoisXML
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
                    (datetime.now(created_dt.tzinfo) - created_dt).days / 365,
                    2
                )

    except Exception:
        pass

    return info


def score_domain(info):
    score = 0
    reasons = []

    # Domain age scoring
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

    # IP address unavailable
    if info["ip"] == "Unavailable":
        score += 5
        reasons.append("Unable to resolve domain IP address")

    return score, reasons
