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