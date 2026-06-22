import requests
from config import GOOGLE_SAFE_BROWSING_API_KEY

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"

    payload = {
        "client": {
            "clientId": "ai-phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=5)
        data = response.json()

        if "matches" in data:
            return {
                "status": "Malicious",
                "reason": "Detected by Google Safe Browsing"
            }
        else:
            return {
                "status": "Safe",
                "reason": "No threats found in Google Safe Browsing"
            }

    except Exception as e:
        return {
            "status": "Unknown",
            "reason": "API error: {str(e)}"
        }
