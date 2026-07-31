"""
Module 3: Reconnaissance

run_fingerprint() = REAL (sends actual HTTP request, inspects headers)
run_crawl() = REAL (parses actual HTML for links/scripts)
"""

import requests
from bs4 import BeautifulSoup


def run_fingerprint(state) -> dict:
    print(f"[recon] Fingerprinting {state['target_url']} ...")

    response = requests.get(state["target_url"])
    headers = response.headers

    tech_stack = {
        "status_code": response.status_code,
        "server_header": headers.get("Server", "not disclosed"),
        "powered_by": headers.get("X-Powered-By", "not disclosed"),
        "security_headers_present": {
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
        },
    }

    # Check for any unusual/leaked headers (like Juice Shop's hidden hint)
    leaked_paths = []
    for key, value in headers.items():
        if key.lower() not in [
            "content-type", "content-length", "date", "connection",
            "cache-control", "etag", "vary", "keep-alive", "accept-ranges",
            "transfer-encoding", "content-encoding", "last-modified",
        ]:
            leaked_paths.append(f"{key}: {value}")

    tech_stack["unusual_headers"] = leaked_paths

    return {
        "finding_type": "fingerprint",
        "data": {"tech_stack": tech_stack},
        "chain_trigger": False,
        "chain_data": None,
    }


def run_crawl(state) -> dict:
    print(f"[recon] Crawling {state['target_url']} ...")

    response = requests.get(state["target_url"])
    soup = BeautifulSoup(response.text, "html.parser")

    # Grab actual links/scripts referenced in the page
    discovered = set()
    for tag in soup.find_all(["a", "script", "link"]):
        src = tag.get("href") or tag.get("src")
        if src:
            discovered.add(src)

    return {
        "finding_type": "crawl",
        "data": {"discovered_pages": list(discovered)},
        "chain_trigger": False,
        "chain_data": None,
    }