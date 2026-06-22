import requests
from bs4 import BeautifulSoup


def crawl_site(url):
    result = {
        "redirects": 0,
        "final_url": url,
        "password_fields": 0,
        "external_links": 0,
        "text": ""
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        result["redirects"] = len(response.history)
        result["final_url"] = response.url

        soup = BeautifulSoup(response.text, "html.parser")

        result["password_fields"] = len(
            soup.find_all("input", {"type": "password"})
        )

        result["external_links"] = len(soup.find_all("a"))
        result["text"] = soup.get_text(" ", strip=True)[:5000]

    except:
        pass

    return result
