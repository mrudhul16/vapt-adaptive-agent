# ------------------------------------------------------------------
# Computed severity model
#
# Severity is NOT a fixed per-category label. It is derived from three axes:
#   1. inherent impact of the vulnerability class (base, 0-10)
#   2. confidence in the finding (confirmed > suspected > potential)
#   3. context signals that raise real-world impact (auth bypass, cross-user
#      access, data exposure, unauthenticated reachability)
# and mapped to a CVSS-style band. This makes, e.g., a *confirmed* IDOR rank
# far above a *potential* DOM-XSS lead, instead of a flat type->label map.
# ------------------------------------------------------------------

_BASE_IMPACT = {
    "sqli": 9.0,            # injection
    "idor": 8.0,            # broken object-level authorization (BOLA)
    "authorization": 7.0,   # broken access control / excessive data exposure
    "xss": 6.0,             # cross-site scripting
    "auth": 4.0,            # auth weaknesses (user enumeration, weak handling)
}

_CONFIDENCE = {
    "confirmed": 1.0,
    "suspected": 0.7,
    "potential": 0.5,
    "info": 0.0,
    "pass": 0.0,
}

_BANDS = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]

_CLASS = {
    "CRITICAL": ("sev-critical", "badge-critical"),
    "HIGH": ("sev-high", "badge-high"),
    "MEDIUM": ("sev-medium", "badge-medium"),
    "LOW": ("sev-low", "badge-low"),
    "INFO": ("sev-info", "badge-info"),
}


def compute_severity(category: str, status: str = "confirmed", context: dict | None = None) -> dict:
    """Compute a finding's severity from type, confidence, and context.

    Returns {"label", "score", "class", "badge"} where score is 0-10.
    """
    category = str(category or "").lower()
    status = str(status or "confirmed").lower()
    context = context or {}

    if category in {"recon", "fingerprint", "crawl", "info"}:
        return {"label": "INFO", "score": 0.0, "class": "sev-info", "badge": "badge-info"}

    base = _BASE_IMPACT.get(category, 5.0)
    confidence = _CONFIDENCE.get(status, 1.0)
    score = base * confidence

    # Context signals that increase real-world impact.
    if context.get("authentication_bypass_verified"):
        score += 1.5
    if context.get("cross_user_access"):
        score += 0.8
    if context.get("multiple_records_exposed"):
        score += 0.6
    if context.get("unauthenticated"):
        score += 0.5

    score = max(0.0, min(score, 10.0))

    label = "INFO"
    for threshold, name in _BANDS:
        if score >= threshold:
            label = name
            break

    css, badge = _CLASS[label]
    return {"label": label, "score": round(score, 1), "class": css, "badge": badge}


def get_impact(category: str) -> str:
    impacts = {
        "sqli": "Unauthorized database access or manipulation may be possible through crafted input.",
        "idor": "Unauthorized access to another user's resources may be possible.",
        "xss": "Client-side script execution in the application context.",
        "auth": "Improper authentication behavior may allow unauthorized access.",
        "fingerprint": "Application and server information was identified during reconnaissance.",
        "crawl": "Application resources and endpoints were discovered during crawling.",
        "error": "An application error was observed during assessment.",
    }

    return impacts.get(
        category.lower(),
        "Potential security impact identified during the assessment."
    )


def get_remediation(category: str) -> str:
    remediations = {
        "sqli": "Use parameterized queries, prepared statements, and strict server-side input validation.",
        "idor": "Enforce server-side authorization checks for every requested resource and verify resource ownership.",
        "xss": "Apply contextual output encoding and appropriate input validation.",
        "auth": "Implement strong authentication controls, secure session handling, and server-side authorization checks.",
        "fingerprint": "Minimize unnecessary server and technology disclosure through HTTP response headers.",
        "crawl": "Review exposed resources and restrict access to sensitive application files and endpoints.",
        "error": "Handle errors securely and avoid exposing sensitive application or server information.",
    }

    return remediations.get(
        category.lower(),
        "Review the affected functionality and apply appropriate security controls."
    )


def is_vulnerable(finding: dict) -> bool:
    if finding.get("vulnerable") is True:
        return True

    data = finding.get("data")

    if isinstance(data, dict):
        if data.get("vulnerable") is True:
            return True

        findings = data.get("findings")

        if isinstance(findings, list) and len(findings) > 0:
            return True

    return False


def analyze_finding(finding: dict) -> dict | None:
    category = str(
        finding.get("finding_type")
        or finding.get("category")
        or "unknown"
    ).lower()

    if category in {"recon", "fingerprint", "crawl"}:
        return {
            "category": category,
            "impact": get_impact(category),
            "remediation": get_remediation(category),
        }

    if not is_vulnerable(finding):
        return None

    return {
        "category": category,
        "impact": get_impact(category),
        "remediation": get_remediation(category),
    }


def analyze_all(findings: list) -> list:
    risks = []

    for finding in findings:
        risk = analyze_finding(finding)

        if risk is not None:
            risks.append(risk)

    return risks