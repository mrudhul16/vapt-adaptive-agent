import re
from urllib.parse import urlparse

import requests


LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1"
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
    "credential",
    "credentials"
}


def is_local_target(url):
    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in {"http", "https"}
            and parsed.hostname in LOCAL_HOSTS
        )

    except Exception:
        return False


def create_session():
    session = requests.Session()

    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "Chrome/154.0.0.0 Safari/537.36"
        )
    })

    return session


def sanitize_text(text):
    if not text:
        return ""

    text = str(text)

    text = re.sub(
        r"Bearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [REDACTED]",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'"(token|jwt|access_token|refresh_token|authorization|cookie|session)"\s*:\s*"[^"]*"',
        r'"\1":"[REDACTED]"',
        text,
        flags=re.IGNORECASE
    )

    return text[:2000]


def sanitize_headers(headers):
    if not headers:
        return {}

    safe = {}

    for key, value in headers.items():
        key_lower = str(key).lower()

        if any(
            sensitive in key_lower
            for sensitive in SENSITIVE_KEYS
        ):
            continue

        safe[str(key)] = str(value)[:300]

    return safe


def detect_authentication_indicators(response):
    body = sanitize_text(
        response.text
    ).lower()

    status = response.status_code

    login_indicators = [
        "login",
        "sign in",
        "signin",
        "username",
        "email",
        "password"
    ]

    auth_required_indicators = [
        "unauthorized",
        "authentication required",
        "not authenticated",
        "access denied",
        "please log in",
        "login required"
    ]

    authenticated_indicators = [
        "authenticated",
        "logged in",
        "welcome",
        "profile",
        "account"
    ]

    return {
        "login_indicators": [
            item
            for item in login_indicators
            if item in body
        ],
        "authentication_required": (
            status in {401, 403}
            or any(
                item in body
                for item in auth_required_indicators
            )
        ),
        "authenticated_indicators": [
            item
            for item in authenticated_indicators
            if item in body
        ]
    }


def analyze_security_question(response):
    raw = response.text or ""
    body = sanitize_text(raw).lower()

    question_words = [
        "question",
        "security question",
        "security_question"
    ]

    answer_words = [
        "answer",
        "security answer",
        "security_answer"
    ]

    question_present = any(
        word in body
        for word in question_words
    )

    answer_present = any(
        word in body
        for word in answer_words
    )

    # A populated security question returned for a supplied email means the
    # endpoint discloses account-specific data (the question) unauthenticated.
    # An empty object ({}) means no such account / nothing disclosed.
    security_question_disclosed = (
        response.status_code == 200
        and '"question"' in body
        and len(raw.strip()) > 10
    )

    return {
        "status_code": response.status_code,
        "question_present": question_present,
        "answer_present": answer_present,
        "email_present": "email" in body,
        "security_question_disclosed": security_question_disclosed,
        "response_length": len(raw.strip()),
    }


def _random_nonexistent_email():
    import uuid
    return f"nonexistent-{uuid.uuid4().hex[:10]}@example.invalid"


def _email_from_url(url):
    """Extract an ?email= value from a URL if present and non-empty."""
    try:
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        for key in ("email", "user", "username"):
            vals = qs.get(key)
            if vals and vals[0].strip():
                return vals[0].strip()
    except Exception:
        pass
    return None


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _harvest_emails(recon_state, limit=5):
    """Collect up to `limit` distinct email addresses from recon data so the
    enumeration probe has real candidates to differentiate against."""
    if not isinstance(recon_state, dict):
        return []
    found = []
    seen = set()
    try:
        import json as _json
        blob = _json.dumps(recon_state, default=str)
    except Exception:
        blob = str(recon_state)
    for match in _EMAIL_RE.findall(blob):
        email = match.strip().lower()
        if email.endswith(".invalid") or email in seen:
            continue
        seen.add(email)
        found.append(email)
        if len(found) >= limit:
            break
    return found


def detect_security_question_enumeration(base_url, candidate_emails=None):
    """
    Detection-only user-enumeration check for the security-question endpoint.

    Sends an unauthenticated request for a known-nonexistent email (control)
    and, if any candidate emails are available, for each candidate. A
    materially different, account-specific response for a candidate (the
    security question is disclosed) while the control returns nothing
    demonstrates user enumeration. No credentials are submitted.
    """
    endpoint = base_url.rstrip("/") + "/rest/user/security-question"
    session = create_session()

    result = {
        "endpoint": endpoint,
        "enumeration_detected": False,
        "security_question_disclosed": False,
        "candidates_tested": 0,
        "disclosed_for": [],
        "detail": (
            "Security-question endpoint probed with a non-existent email; "
            "no enumeration observed."
        ),
    }

    try:
        control = analyze_security_question(
            session.get(
                endpoint,
                params={"email": _random_nonexistent_email()},
                timeout=8,
            )
        )
    except requests.RequestException as exc:
        result["error"] = type(exc).__name__
        return result

    result["control_response_length"] = control["response_length"]

    for email in (candidate_emails or []):
        if not email:
            continue
        result["candidates_tested"] += 1
        try:
            probe = analyze_security_question(
                session.get(endpoint, params={"email": email}, timeout=8)
            )
        except requests.RequestException:
            continue

        if (
            probe["security_question_disclosed"]
            and not control["security_question_disclosed"]
        ):
            result["enumeration_detected"] = True
            result["security_question_disclosed"] = True
            # Record only that this address resolved to an account (no PII dump).
            result["disclosed_for"].append(email)

    if result["enumeration_detected"]:
        result["detail"] = (
            "Unauthenticated security-question endpoint returns account-"
            "specific data for a valid email but an empty response for a "
            "non-existent one, enabling user enumeration and exposing the "
            "account's security question."
        )

    return result


def analyze_login_response(response):
    status = response.status_code
    body = sanitize_text(
        response.text
    ).lower()

    success_words = [
        "success",
        "authenticated",
        "logged in",
        "login successful"
    ]

    failure_words = [
        "invalid",
        "incorrect",
        "unauthorized",
        "wrong password",
        "login failed"
    ]

    login_successful = (
        status in {200, 201}
        and any(
            word in body
            for word in success_words
        )
        and not any(
            word in body
            for word in failure_words
        )
    )

    suspicious = False
    indicators = []

    if status == 200 and not body.strip():
        suspicious = True
        indicators.append(
            "Empty successful response from login endpoint"
        )

    if status in {200, 201} and "unauthorized" in body:
        indicators.append(
            "Successful HTTP status with unauthorized message"
        )

    if status == 500:
        indicators.append(
            "Server error observed during login request"
        )

    return {
        "status_code": status,
        "login_successful": login_successful,
        "suspicious_behavior": suspicious,
        "indicators": indicators
    }


def analyze_password_reset(response):
    status = response.status_code
    body = sanitize_text(
        response.text
    ).lower()

    enumeration_indicators = [
        "email not found",
        "user not found",
        "account not found",
        "does not exist",
        "no user",
        "invalid email"
    ]

    enumeration_detected = any(
        indicator in body
        for indicator in enumeration_indicators
    )

    return {
        "status_code": status,
        "user_enumeration_indicator": enumeration_detected,
        "detail": (
            "Password reset response analyzed "
            "without submitting reset credentials."
        )
    }


def analyze_change_password(response):
    status = response.status_code

    return {
        "status_code": status,
        "authentication_required": status in {401, 403},
        "password_change_attempted": False,
        "detail": (
            "Change-password endpoint analyzed "
            "without modifying credentials."
        )
    }


def analyze_whoami(response):
    status = response.status_code
    body = sanitize_text(
        response.text
    ).lower()

    protected = status in {401, 403}

    identity_indicators = [
        "username",
        "email",
        "userid",
        "user_id",
        "role"
    ]

    identity_exposed = any(
        indicator in body
        for indicator in identity_indicators
    )

    suspicious = (
        status == 200
        and identity_exposed
    )

    return {
        "status_code": status,
        "authentication_required": protected,
        "identity_information_present": identity_exposed,
        "suspicious_unauthenticated_access": suspicious
    }


def analyze_authentication_details(response):
    status = response.status_code
    body = sanitize_text(
        response.text
    ).lower()

    sensitive_auth_words = [
        "password",
        "security answer",
        "secret",
        "token",
        "session"
    ]

    sensitive_content_present = any(
        word in body
        for word in sensitive_auth_words
    )

    return {
        "status_code": status,
        "authentication_required": status in {401, 403},
        "sensitive_authentication_content_present": (
            sensitive_content_present
            if status == 200
            else False
        )
    }


def analyze_registration(response):
    status = response.status_code
    body = sanitize_text(
        response.text
    ).lower()

    account_created = any(
        phrase in body
        for phrase in [
            "account created",
            "registration successful",
            "registered successfully"
        ]
    )

    return {
        "status_code": status,
        "registration_detected": account_created,
        "account_creation_attempted": False,
        "detail": (
            "Registration endpoint analyzed "
            "without creating an account."
        )
    }


def generic_auth_analysis(response):
    indicators = detect_authentication_indicators(
        response
    )

    return {
        "status_code": response.status_code,
        "authentication_required": indicators[
            "authentication_required"
        ],
        "login_indicators": indicators[
            "login_indicators"
        ],
        "authenticated_indicators": indicators[
            "authenticated_indicators"
        ]
    }


def execute_auth_test(recon_state, target):
    if not isinstance(target, dict):
        return {
            "success": False,
            "status": "invalid_target",
            "error": "Target must be a dictionary"
        }

    url = str(
        target.get("url", "")
    ).strip()

    if not url:
        return {
            "success": False,
            "status": "invalid_target",
            "error": "Target URL missing"
        }

    if not is_local_target(url):
        return {
            "success": False,
            "status": "blocked",
            "error": "Only authorized local targets are allowed"
        }

    target_type = str(
        target.get("type", "endpoint")
    ).lower()

    method = str(
        target.get("method", "GET")
    ).upper()

    session = create_session()

    try:
        response = session.request(
            method=method,
            url=url,
            timeout=10,
            allow_redirects=True
        )

        lower_url = url.lower()

        if (
            "/login" in lower_url
            or "/authenticate" in lower_url
        ):
            analysis = analyze_login_response(
                response
            )

            result = {
                "vulnerable": (
                    analysis[
                        "suspicious_behavior"
                    ]
                ),
                "authenticated": (
                    analysis[
                        "login_successful"
                    ]
                ),
                **analysis,
                "detail": (
                    "Login endpoint responded and "
                    "authentication behavior was analyzed."
                )
            }

        elif "/register" in lower_url or "/signup" in lower_url:
            analysis = analyze_registration(
                response
            )

            result = {
                "vulnerable": False,
                "authenticated": False,
                **analysis
            }

        elif (
            "reset-password" in lower_url
            or "forgot-password" in lower_url
        ):
            analysis = analyze_password_reset(
                response
            )

            result = {
                "vulnerable": analysis[
                    "user_enumeration_indicator"
                ],
                "authenticated": False,
                **analysis
            }

        elif "change-password" in lower_url:
            analysis = analyze_change_password(
                response
            )

            result = {
                "vulnerable": (
                    response.status_code == 200
                    and not analysis[
                        "authentication_required"
                    ]
                ),
                "authenticated": False,
                **analysis
            }

        elif (
            "security-question" in lower_url
            or "security_question" in lower_url
        ):
            analysis = analyze_security_question(response)

            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Candidate emails: any carried by the target, plus emails already
            # discovered elsewhere in recon (e.g. exposed user listings). The
            # probe only flags enumeration when a candidate resolves to an
            # account while a random non-existent email does not.
            candidate_emails = []
            carried = _email_from_url(url)
            if carried:
                candidate_emails.append(carried)
            candidate_emails.extend(_harvest_emails(recon_state))

            enumeration = detect_security_question_enumeration(
                base_url,
                candidate_emails=candidate_emails,
            )

            result = {
                "vulnerable": enumeration.get("enumeration_detected", False),
                "suspected": enumeration.get("security_question_disclosed", False),
                "authenticated": False,
                **analysis,
                "enumeration": enumeration,
                "detail": enumeration.get(
                    "detail",
                    "Security-question endpoint analyzed without submitting an answer.",
                ),
            }

        elif (
            "security-answer" in lower_url
            or "security_answer" in lower_url
        ):
            result = {
                "vulnerable": (
                    response.status_code == 200
                    and "unauthorized" not in
                    sanitize_text(
                        response.text
                    ).lower()
                ),
                "authenticated": False,
                "status_code": response.status_code,
                "detail": (
                    "Security-answer endpoint "
                    "analyzed without submitting an answer."
                )
            }

        elif "whoami" in lower_url:
            analysis = analyze_whoami(
                response
            )

            result = {
                "vulnerable": analysis[
                    "suspicious_unauthenticated_access"
                ],
                "authenticated": (
                    not analysis[
                        "authentication_required"
                    ]
                    and analysis[
                        "identity_information_present"
                    ]
                ),
                **analysis,
                "detail": (
                    "Authenticated-user endpoint analyzed."
                )
            }

        elif (
            "authentication-details" in lower_url
            or "authentication_details" in lower_url
        ):
            analysis = analyze_authentication_details(
                response
            )

            result = {
                "vulnerable": (
                    analysis[
                        "sensitive_authentication_content_present"
                    ]
                    and not analysis[
                        "authentication_required"
                    ]
                ),
                "authenticated": False,
                **analysis,
                "detail": (
                    "Authentication endpoint analyzed."
                )
            }

        elif (
            "/auth" in lower_url
            or "/session" in lower_url
        ):
            analysis = generic_auth_analysis(
                response
            )

            result = {
                "vulnerable": (
                    response.status_code == 200
                    and analysis[
                        "authentication_required"
                    ] is False
                    and len(
                        analysis[
                            "authenticated_indicators"
                        ]
                    ) > 0
                ),
                "authenticated": False,
                **analysis,
                "detail": (
                    "Authentication/session endpoint "
                    "analyzed."
                )
            }

        else:
            analysis = generic_auth_analysis(
                response
            )

            result = {
                "vulnerable": False,
                "authenticated": False,
                **analysis,
                "detail": (
                    "Authentication-related endpoint "
                    "analyzed."
                )
            }

        return {
            "success": True,
            "status": "completed",
            "data": result
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "status": "timeout",
            "error": "Authentication request timed out"
        }

    except requests.exceptions.ConnectionError:
        return {
            "success": False,
            "status": "connection_error",
            "error": "Unable to connect to local target"
        }

    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "status": "request_error",
            "error": type(e).__name__
        }

    except Exception as e:
        return {
            "success": False,
            "status": "error",
            "error": type(e).__name__
        }