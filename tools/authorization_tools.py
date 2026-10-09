import re
from urllib.parse import urlparse

import requests


LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
}


SENSITIVE_KEYS = {
    "token",
    "jwt",
    "authorization",
    "cookie",
    "session",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
}


def validate_local_target(url: str) -> bool:
    try:
        parsed = urlparse(url)

        if parsed.scheme not in {"http", "https"}:
            return False

        return parsed.hostname in LOCAL_HOSTS

    except Exception:
        return False


def sanitize_text(text: str, max_length: int = 1200) -> str:
    if not text:
        return ""

    text = str(text)

    text = re.sub(
        r"Bearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [REDACTED]",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r'("(?:token|jwt|authorization|cookie|session|access_token|refresh_token|password|secret)"\s*:\s*)("[^"]*"|[^,\\}\s]+)',
        r'\1"[REDACTED]"',
        text,
        flags=re.IGNORECASE,
    )

    if len(text) > max_length:
        text = text[:max_length] + "...[TRUNCATED]"

    return text


def sanitize_headers(headers: dict) -> dict:
    sanitized = {}

    for key, value in headers.items():
        lower_key = str(key).lower()

        if any(secret in lower_key for secret in SENSITIVE_KEYS):
            sanitized[str(key)] = "[REDACTED]"
        else:
            sanitized[str(key)] = sanitize_text(
                str(value),
                500,
            )

    return sanitized


def safe_response_data(response: requests.Response) -> dict:
    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    text = response.text or ""

    return {
        "status_code": response.status_code,
        "content_type": content_type,
        "content_length": len(text),
        "headers": sanitize_headers(
            dict(response.headers)
        ),
        "preview": sanitize_text(text),
    }


def detect_authentication_requirement(
    status_code: int,
    body: str,
    headers: dict,
) -> bool:

    if status_code in {401, 403}:
        return True

    text = (body or "").lower()

    indicators = [
        "unauthorized",
        "authentication required",
        "authorization required",
        "no authorization header",
        "access denied",
        "forbidden",
        "login required",
        "jwt",
        "bearer token",
    ]

    for indicator in indicators:
        if indicator in text:
            return True

    header_text = " ".join(
        f"{key}:{value}"
        for key, value in headers.items()
    ).lower()

    if "www-authenticate" in header_text:
        return True

    return False


def detect_authorization_indicators(
    url: str,
    body: str,
) -> list:

    indicators = []

    lower_url = url.lower()
    lower_body = (body or "").lower()

    keyword_map = {
        "admin": [
            "/admin",
            "administrator",
            "admin panel",
            "administration",
        ],
        "user": [
            "/user",
            "/users",
            "user profile",
            "user account",
        ],
        "account": [
            "/account",
            "account details",
        ],
        "address": [
            "/address",
            "saved address",
        ],
        "role": [
            "role",
            "privilege",
            "permission",
        ],
    }

    combined = lower_url + " " + lower_body

    for name, keywords in keyword_map.items():
        if any(
            keyword in combined
            for keyword in keywords
        ):
            indicators.append(name)

    return list(
        dict.fromkeys(indicators)
    )


def is_frontend_shell(
    response: requests.Response,
    body: str,
) -> bool:

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    if "text/html" not in content_type:
        return False

    text = (body or "").lower()

    frontend_markers = [
        "<!doctype html",
        "<html",
        "<app-root",
        "ng-version",
        "runtime.",
        "polyfills.",
        "main.",
        "assets/",
        "owasp juice shop",
        "data-beasties-container",
    ]

    marker_count = sum(
        1
        for marker in frontend_markers
        if marker in text
    )

    return marker_count >= 2


def is_backend_target(
    url: str,
    target: dict,
) -> bool:

    lower_url = url.lower()

    target_type = str(
        target.get("type", "")
    ).lower()

    backend_markers = [
        "/api/",
        "/rest/",
        "/graphql",
        "/oauth",
        "/auth/",
        "/authentication",
        "/session",
        "/users/",
        "/user/",
        "/account/",
        "/address/",
        "/admin/",
        "/orders/",
        "/basket/",
        "/payment/",
    ]

    if any(
        marker in lower_url
        for marker in backend_markers
    ):
        return True

    if target_type in {
        "api",
        "rest",
        "json",
        "backend",
    }:
        return True

    return False


def analyze_authorization_response(
    target: dict,
    response: requests.Response,
    authenticated_request: bool = False,
    baseline_status_code=None,
    baseline_authentication_required: bool = False,
    authenticated_user_id=None,
) -> dict:

    url = target.get(
        "url",
        "",
    )

    body = response.text or ""

    status_code = response.status_code

    headers = dict(
        response.headers
    )

    frontend_shell = is_frontend_shell(
        response,
        body,
    )

    backend_target = is_backend_target(
        url,
        target,
    )

    authentication_required = detect_authentication_requirement(
        status_code,
        body,
        headers,
    )

    indicators = detect_authorization_indicators(
        url,
        body,
    )

    unauthorized_access = False
    suspicious_behavior = False
    vulnerable = False
    authorization_bypass = False
    suspected = False
    confirmed = False
    inconclusive = False
    multiple_user_records_exposed = False

    detail = "Authorization behavior analyzed."

    if authenticated_request:

        if status_code in {401, 403}:
            detail = (
                "Authenticated request was still denied by the endpoint."
            )

        elif frontend_shell and not backend_target:
            detail = (
                "Authenticated request returned a frontend application page. "
                "No backend authorization bypass was established."
            )

        elif backend_target:

            content_type = headers.get(
                "Content-Type",
                "",
            ).lower()

            is_json = (
                "application/json" in content_type
                or body.strip().startswith("{")
                or body.strip().startswith("[")
            )

            if status_code in {
                200,
                201,
                202,
                204,
                206,
            } and is_json:
                try:
                    import json
                    resp_data = json.loads(body)
                    
                    items = (
                        resp_data.get("data", resp_data)
                        if isinstance(resp_data, dict)
                        else resp_data
                    )
                    
                    mismatched_owner_ids = set()
                    extracted_owner_ids = set()
                    
                    if isinstance(items, dict):
                        for key in ("UserId", "userId", "user_id"):
                            if key in items:
                                extracted_owner_ids.add(str(items[key]))
                                if authenticated_user_id is not None and str(items[key]) != str(authenticated_user_id):
                                    mismatched_owner_ids.add(str(items[key]))
                                break
                    elif isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                for key in ("UserId", "userId", "user_id"):
                                    if key in item:
                                        extracted_owner_ids.add(str(item[key]))
                                        if authenticated_user_id is not None and str(item[key]) != str(authenticated_user_id):
                                            mismatched_owner_ids.add(str(item[key]))
                                        break
                    
                    mismatched_owners_str = ", ".join(sorted(list(mismatched_owner_ids)))
                    extracted_owners_str = ", ".join(sorted(list(extracted_owner_ids)))
                    
                    is_user_list = (
                        isinstance(items, list)
                        and len(items) > 1
                        and any(
                            isinstance(item, dict) and "email" in item
                            for item in items
                        )
                    )

                    if extracted_owner_ids and authenticated_user_id is None:
                        inconclusive = True
                        detail = (
                            f"Resource returned owner IDs ({extracted_owners_str}) but "
                            "authenticated_user_id is missing. Inconclusive ownership check."
                        )
                    elif mismatched_owner_ids:
                            suspicious_behavior = True
                            vulnerable = True
                            authorization_bypass = False
                            suspected = True
                            confirmed = False
                            unauthorized_access = False
                            multiple_user_records_exposed = False
                            detail = (
                                f"Authenticated request successfully accessed resource(s) "
                                f"belonging to other users (owner IDs: {mismatched_owners_str}, "
                                f"authenticated ID: {authenticated_user_id}). This is a strong signal "
                                f"of IDOR/BOLA, but requires policy verification to confirm."
                            )
                    elif is_user_list:
                        suspicious_behavior = True
                        vulnerable = True
                        authorization_bypass = False
                        suspected = True
                        confirmed = False
                        unauthorized_access = False
                        multiple_user_records_exposed = True
                        detail = (
                            "Authenticated request successfully reached a backend "
                            "resource and returned multiple user records. "
                            "This indicates potential excessive data exposure, "
                            "but requires verification of the expected authorization policy."
                        )
                    else:
                        detail = (
                            "Authenticated request successfully reached a backend "
                            "resource. No privilege-boundary bypass was established "
                            "without evidence of an unauthorized role or owner."
                        )
                except Exception:
                    detail = (
                        "Authenticated request successfully reached a backend "
                        "resource. No privilege-boundary bypass was established "
                        "without evidence of an unauthorized role or owner."
                    )
            elif status_code in {200, 201, 202, 204, 206} and baseline_authentication_required:
                detail = (
                    "Authenticated request reached the protected endpoint. "
                    "Successful authenticated access alone does not establish "
                    "an authorization vulnerability."
                )
            elif 200 <= status_code < 300:
                detail = (
                    "Authenticated request succeeded, but the response did "
                    "not provide sufficient evidence of an authorization bypass."
                )
            else:
                detail = (
                    "Authenticated backend request completed without evidence "
                    "of an authorization bypass."
                )

        else:
            detail = (
                "Authenticated request completed without evidence "
                "of an authorization bypass."
            )

    elif frontend_shell and not backend_target:

        detail = (
            "Frontend application page was accessible. "
            "No backend authorization bypass was established."
        )

    elif status_code in {401, 403}:

        detail = (
            "Endpoint enforced an authentication "
            "or authorization boundary."
        )

    elif backend_target:

        if status_code == 200:

            content_type = headers.get(
                "Content-Type",
                "",
            ).lower()

            is_json = (
                "application/json" in content_type
                or body.strip().startswith("{")
                or body.strip().startswith("[")
            )

            if is_json:

                if baseline_authentication_required:
                    unauthorized_access = True
                    suspicious_behavior = True
                    vulnerable = True
                    authorization_bypass = True
                    suspected = True
                    confirmed = False

                    detail = (
                        "Backend resource that typically requires authentication "
                        "returned JSON successfully without authentication. "
                        "Requires verification to confirm unauthorized data exposure."
                    )
                else:
                    unauthorized_access = False
                    suspicious_behavior = False
                    vulnerable = False
                    authorization_bypass = False
                    suspected = False
                    confirmed = False

                    detail = (
                        "Backend resource returned JSON successfully without authentication. "
                        "This may be a public API."
                    )

            else:

                detail = (
                    "Backend target returned a successful "
                    "non-JSON response; authorization bypass "
                    "was not confirmed."
                )

        elif status_code in {
            204,
            206,
        }:

            if baseline_authentication_required:
                unauthorized_access = True
                suspicious_behavior = True
                vulnerable = True
                authorization_bypass = True
                suspected = True
                confirmed = False

                detail = (
                    "Backend resource that typically requires authentication "
                    "returned successfully (204/206) without an authentication boundary."
                )
            else:
                unauthorized_access = False
                suspicious_behavior = False
                vulnerable = False
                authorization_bypass = False
                suspected = False
                confirmed = False
                
                detail = (
                    "Backend resource returned successfully (204/206) "
                    "without authentication. This may be public."
                )

        elif 200 <= status_code < 300:

            detail = (
                "Backend endpoint responded successfully, "
                "but authorization bypass was not confirmed."
            )

        else:

            detail = (
                "Backend endpoint did not provide evidence "
                "of unauthorized access."
            )

    else:

        detail = (
            "Public frontend route was accessible; "
            "no authorization vulnerability was confirmed."
        )

    return {
        "vulnerable": vulnerable,
        "suspected": suspected,
        "confirmed": confirmed,
        "inconclusive": inconclusive,
        "multiple_user_records_exposed": multiple_user_records_exposed,
        "unauthorized_access": unauthorized_access,
        "authorization_bypass": authorization_bypass,
        "authenticated_request": authenticated_request,
        "authentication_required": authentication_required,
        "suspicious_behavior": suspicious_behavior,
        "status_code": status_code,
        "baseline_status_code": baseline_status_code,
        "baseline_authentication_required": (
            baseline_authentication_required
        ),
        "indicators": indicators,
        "frontend_shell": frontend_shell,
        "backend_target": backend_target,
        "target": target,
        "detail": detail,
        "response_headers": sanitize_headers(
            headers
        ),
        "response_preview": sanitize_text(
            body
        ),
    }


def _build_authenticated_session(
    auth_session: dict,
) -> requests.Session:

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/154.0 Safari/537.36"
            )
        }
    )

    headers = auth_session.get(
        "headers"
    )

    if isinstance(headers, dict):

        for key, value in headers.items():

            lower_key = str(key).lower()

            if lower_key in {
                "authorization",
                "cookie",
                "set-cookie",
            }:

                session.headers[
                    str(key)
                ] = str(value)

    token = auth_session.get(
        "token"
    )

    if token:
        session.headers[
            "Authorization"
        ] = f"Bearer {token}"

    access_token = auth_session.get(
        "access_token"
    )

    if access_token:
        session.headers[
            "Authorization"
        ] = f"Bearer {access_token}"

    cookie_value = auth_session.get(
        "cookie"
    )

    if cookie_value:
        session.headers[
            "Cookie"
        ] = str(cookie_value)

    cookies = auth_session.get(
        "cookies"
    )

    if isinstance(cookies, dict):

        for key, value in cookies.items():

            session.cookies.set(
                str(key),
                str(value),
            )

    return session


def _perform_authorization_request(
    session: requests.Session,
    target: dict,
) -> requests.Response:

    url = target.get(
        "url",
        "",
    )

    method = str(
        target.get(
            "method",
            "GET",
        )
    ).upper()

    if method == "HEAD":

        return session.head(
            url,
            timeout=10,
            allow_redirects=True,
        )

    if method == "POST":

        return session.post(
            url,
            timeout=10,
            allow_redirects=True,
        )

    if method == "PUT":

        return session.put(
            url,
            timeout=10,
            allow_redirects=True,
        )

    if method == "DELETE":

        return session.delete(
            url,
            timeout=10,
            allow_redirects=True,
        )

    if method == "PATCH":

        return session.patch(
            url,
            timeout=10,
            allow_redirects=True,
        )

    return session.get(
        url,
        timeout=10,
        allow_redirects=True,
    )


def execute_authorization_test(
    recon_state: dict,
    target: dict,
) -> dict:

    if not isinstance(target, dict):

        return {
            "success": False,
            "status": "failed",
            "data": {
                "vulnerable": False,
                "detail": "Invalid authorization target.",
            },
        }

    url = target.get(
        "url",
        "",
    )

    if not url:

        return {
            "success": False,
            "status": "failed",
            "data": {
                "vulnerable": False,
                "detail": (
                    "Authorization target has no URL."
                ),
            },
        }

    if not validate_local_target(url):

        return {
            "success": False,
            "status": "failed",
            "data": {
                "vulnerable": False,
                "detail": (
                    "Target rejected because it is not "
                    "a local authorized target."
                ),
            },
        }

    try:

        baseline_session = requests.Session()

        baseline_session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/154.0 Safari/537.36"
                )
            }
        )

        baseline_response = (
            _perform_authorization_request(
                baseline_session,
                target,
            )
        )

        baseline_analysis = (
            analyze_authorization_response(
                target,
                baseline_response,
                authenticated_request=False,
            )
        )

        auth_session = None

        if isinstance(
            recon_state,
            dict,
        ):

            candidate = recon_state.get(
                "authenticated_session"
            )

            if isinstance(
                candidate,
                dict,
            ):

                auth_session = candidate

        if auth_session:

            authenticated_session = (
                _build_authenticated_session(
                    auth_session
                )
            )

            authenticated_response = (
                _perform_authorization_request(
                    authenticated_session,
                    target,
                )
            )

            from tools.idor_tools import _get_authenticated_user_id
            current_user_id = _get_authenticated_user_id(auth_session)

            authenticated_analysis = (
                analyze_authorization_response(
                    target,
                    authenticated_response,
                    authenticated_request=True,
                    baseline_status_code=(
                        baseline_response.status_code
                    ),
                    baseline_authentication_required=(
                        baseline_analysis.get(
                            "authentication_required",
                            False,
                        )
                    ),
                    authenticated_user_id=current_user_id,
                )
            )

            combined = dict(
                authenticated_analysis
            )

            combined["baseline"] = {
                "status_code": (
                    baseline_analysis.get(
                        "status_code"
                    )
                ),
                "authentication_required": (
                    baseline_analysis.get(
                        "authentication_required"
                    )
                ),
                "frontend_shell": (
                    baseline_analysis.get(
                        "frontend_shell"
                    )
                ),
                "backend_target": (
                    baseline_analysis.get(
                        "backend_target"
                    )
                ),
                "detail": (
                    baseline_analysis.get(
                        "detail"
                    )
                ),
            }

            combined[
                "authenticated_request"
            ] = True

            combined[
                "authenticated_status_code"
            ] = authenticated_response.status_code

            return {
                "success": True,
                "status": "completed",
                "data": combined,
            }

        return {
            "success": True,
            "status": "completed",
            "data": baseline_analysis,
        }

    except requests.RequestException as exc:

        return {
            "success": False,
            "status": "failed",
            "data": {
                "vulnerable": False,
                "unauthorized_access": False,
                "authorization_bypass": False,
                "authenticated_request": False,
                "authentication_required": False,
                "suspicious_behavior": False,
                "target": target,
                "detail": (
                    "Authorization request failed: "
                    + sanitize_text(
                        str(exc)
                    )
                ),
            },
        }

    except Exception as exc:

        return {
            "success": False,
            "status": "failed",
            "data": {
                "vulnerable": False,
                "unauthorized_access": False,
                "authorization_bypass": False,
                "authenticated_request": False,
                "authentication_required": False,
                "suspicious_behavior": False,
                "target": target,
                "detail": (
                    "Unexpected authorization test error: "
                    + sanitize_text(
                        str(exc)
                    )
                ),
            },
        }