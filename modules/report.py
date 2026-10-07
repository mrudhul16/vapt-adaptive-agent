from datetime import datetime


SENSITIVE_KEYS = {
    "token",
    "jwt",
    "password",
    "authorization",
    "cookie",
    "session",
    "access_token",
    "refresh_token",
    "authenticated_session",
    "auth_token",
    "response",
    "storage",
}


def redact_sensitive_data(value):

    if isinstance(value, dict):

        result = {}

        for key, item in value.items():

            if str(key).lower() in SENSITIVE_KEYS:

                result[key] = "[REDACTED]"

            else:

                result[key] = redact_sensitive_data(item)

        return result

    if isinstance(value, list):

        return [
            redact_sensitive_data(item)
            for item in value
        ]

    return value


def format_target(target):

    if not isinstance(target, dict):
        return str(target)

    target_type = target.get(
        "type",
        "target"
    )

    url = target.get(
        "url",
        "N/A"
    )

    if target_type == "login_form":

        return f"Login form ({url})"

    if target_type == "basket_object":

        object_id = target.get(
            "object_id",
            "unknown"
        )

        return (
            f"Basket object {object_id} "
            f"({url})"
        )

    if target_type == "basket_collection":

        return f"Basket collection ({url})"

    if target_type == "input":

        index = target.get(
            "index",
            "unknown"
        )

        return (
            f"Input {index} "
            f"({url})"
        )

    return f"{target_type} ({url})"


def extract_chain_source(chain):

    if not isinstance(chain, dict):
        return "Unknown"

    source = (
        chain.get("source")
        or chain.get("trigger")
        or chain.get("finding_type")
        or chain.get("finding")
    )

    if source:
        return source

    chain_name = chain.get(
        "chain"
    )

    if chain_name == "sqli_to_idor":
        return "SQL Injection"

    if chain_name:
        return chain_name

    reason = str(
        chain.get(
            "reason",
            ""
        )
    )

    if "sql injection" in reason.lower():
        return "SQL Injection"

    return "Unknown"


def extract_chain_destination(chain):

    if not isinstance(chain, dict):
        return "Unknown"

    destination = (
        chain.get("next_module")
        or chain.get("destination")
        or chain.get("next_action")
        or chain.get("module")
    )

    if destination:
        return destination

    if chain.get("chain") == "sqli_to_idor":
        return "idor_check"

    return "Unknown"


def extract_chain_reason(chain):

    if not isinstance(chain, dict):
        return ""

    reason = chain.get(
        "reason"
    )

    if reason:
        return reason

    if chain.get("chain") == "sqli_to_idor":

        return (
            "SQL injection produced an "
            "authenticated session, triggering "
            "the IDOR specialist."
        )

    return ""


def extract_decision_action(decision):

    if not isinstance(decision, dict):
        return "Unknown"

    action = (
        decision.get("action")
        or decision.get("next_action")
        or decision.get("module")
        or decision.get("selected_module")
    )

    if action:
        return action

    reason = str(
        decision.get(
            "reason",
            ""
        )
    )

    reason_lower = reason.lower()

    if (
        "all core modules run"
        in reason_lower
        or "assessment complete"
        in reason_lower
    ):

        return "stop"

    if "chained into" in reason_lower:

        parts = reason.split("'")

        if len(parts) >= 2:
            return parts[1]

    if "chose" in reason_lower:

        parts = reason.split("'")

        if len(parts) >= 2:
            return parts[1]

    return "Unknown"


def extract_decision_reason(decision):

    if not isinstance(decision, dict):
        return ""

    return (
        decision.get("reason")
        or decision.get("explanation")
        or decision.get("message")
        or ""
    )


def summarize_finding(finding):

    if not isinstance(finding, dict):
        return str(finding)

    finding_type = (
        finding.get("finding_type")
        or finding.get("category")
        or "unknown"
    )

    data = finding.get(
        "data",
        {}
    )

    if not isinstance(data, dict):
        return {
            "category": finding_type,
            "detail": str(data)
        }

    summary = {
        "category": finding_type
    }

    if finding_type == "fingerprint":

        summary["detail"] = (
            "Application and server "
            "information identified "
            "during reconnaissance."
        )

        tech_stack = data.get(
            "tech_stack"
        )

        if isinstance(
            tech_stack,
            dict
        ):

            status_code = tech_stack.get(
                "status_code"
            )

            if status_code is not None:

                summary[
                    "status_code"
                ] = status_code

    elif finding_type == "crawl":

        pages = data.get(
            "discovered_pages",
            []
        )

        summary["resources_discovered"] = (
            len(pages)
            if isinstance(pages, list)
            else 0
        )

        summary["detail"] = (
            "Application resources and "
            "endpoints were discovered "
            "during crawling."
        )

    elif finding_type == "auth":

        summary["login_successful"] = (
            data.get(
                "login_successful"
            )
        )

        summary["status_code"] = (
            data.get(
                "status_code"
            )
        )

        summary["detail"] = (
            "Authentication behavior "
            "was tested."
        )

    elif finding_type == "sqli":

        successful = data.get(
            "successful_targets",
            []
        )

        tested = data.get(
            "tested_targets",
            []
        )

        summary[
            "targets_tested"
        ] = len(tested)

        summary[
            "successful_targets"
        ] = len(successful)

        summary["authenticated"] = bool(
            data.get(
                "authenticated"
            )
        )

        summary["detail"] = (
            data.get(
                "detail",
                "SQL injection testing completed."
            )
        )

        if successful:

            summary[
                "successful_target_types"
            ] = [
                target.get(
                    "type",
                    "unknown"
                )
                for target in successful
                if isinstance(
                    target,
                    dict
                )
            ]

    elif finding_type == "idor":

        successful = data.get(
            "successful_targets",
            []
        )

        tested = data.get(
            "tested_targets",
            []
        )

        summary[
            "targets_tested"
        ] = len(tested)

        summary[
            "unauthorized_resources"
        ] = data.get(
            "unauthorized_resource_count",
            len(successful)
        )

        summary["detail"] = (
            data.get(
                "detail",
                "IDOR testing completed."
            )
        )

    elif finding_type == "xss":

        summary[
            "tested_endpoint"
        ] = data.get(
            "tested_endpoint"
        )

        summary["detail"] = (
            data.get(
                "detail",
                "XSS testing completed."
            )
        )

    else:

        safe_data = redact_sensitive_data(
            data
        )

        summary["detail"] = safe_data

    return summary


def generate_report(state) -> str:

    lines = []

    def add(text=""):
        lines.append(text)

    add("=" * 70)
    add(
        "VAPT ADAPTIVE AGENT - SECURITY ASSESSMENT REPORT"
    )
    add("=" * 70)

    # --------------------------------------------------
    # ASSESSMENT OVERVIEW
    # --------------------------------------------------

    add()
    add("ASSESSMENT OVERVIEW")
    add("-" * 70)

    add(
        f"Target: "
        f"{state.get('target_url', 'N/A')}"
    )

    add(
        "Assessment Started: "
        f"{state.get('assessment_start_time', 'N/A')}"
    )

    add(
        "Adaptive Chaining: "
        f"{'Enabled' if state.get('chaining_enabled') else 'Disabled'}"
    )

    # --------------------------------------------------
    # EXECUTION SUMMARY
    # --------------------------------------------------

    add()
    add("EXECUTION SUMMARY")
    add("-" * 70)

    metrics = state.get(
        "metrics",
        {}
    )

    modules_executed = metrics.get(
        "modules_executed",
        len(
            state.get(
                "modules_run",
                []
            )
        )
    )

    workflow_steps = metrics.get(
        "workflow_steps",
        state.get(
            "step_count",
            0
        )
    )

    findings_count = metrics.get(
        "findings_discovered",
        len(
            state.get(
                "findings",
                []
            )
        )
    )

    chains_triggered = metrics.get(
        "chains_triggered",
        0
    )

    chains_completed = metrics.get(
        "chains_completed",
        0
    )

    add(
        f"Modules Executed: {modules_executed}"
    )

    add(
        f"Workflow Steps: {workflow_steps}"
    )

    add(
        f"Findings Discovered: {findings_count}"
    )

    add(
        f"Chains Triggered: {chains_triggered}"
    )

    add(
        f"Chains Completed: {chains_completed}"
    )

    # --------------------------------------------------
    # MODULES
    # --------------------------------------------------

    add()
    add("MODULES EXECUTED")
    add("-" * 70)

    modules = state.get(
        "modules_run",
        []
    )

    if modules:

        for index, module in enumerate(
            modules,
            1
        ):

            add(
                f"{index}. {module}"
            )

    else:

        add(
            "No modules executed."
        )

    # --------------------------------------------------
    # RECONNAISSANCE
    # --------------------------------------------------

    add()
    add("RECONNAISSANCE")
    add("-" * 70)

    tech_stack = state.get(
        "tech_stack",
        {}
    )

    if tech_stack:

        safe_tech_stack = (
            redact_sensitive_data(
                tech_stack
            )
        )

        for key, value in (
            safe_tech_stack.items()
        ):

            add(
                f"{key}: {value}"
            )

    else:

        add(
            "No reconnaissance information available."
        )

    # --------------------------------------------------
    # DISCOVERED RESOURCES
    # --------------------------------------------------

    add()
    add("DISCOVERED RESOURCES")
    add("-" * 70)

    pages = state.get(
        "pages",
        []
    )

    if pages:

        add(
            f"Total resources discovered: "
            f"{len(pages)}"
        )

        for page in pages:

            add(
                f"- {page}"
            )

    else:

        add(
            "No resources discovered."
        )

    # --------------------------------------------------
    # FINDINGS
    # --------------------------------------------------

    add()
    add("SECURITY FINDINGS")
    add("-" * 70)

    findings = state.get(
        "findings",
        []
    )

    if findings:

        for index, finding in enumerate(
            findings,
            1
        ):

            summary = summarize_finding(
                finding
            )

            add(
                f"Finding {index}"
            )

            add(
                f"Category: "
                f"{summary.get('category', 'unknown').upper()}"
            )

            for key, value in summary.items():

                if key == "category":
                    continue

                label = key.replace(
                    "_",
                    " "
                ).title()

                if isinstance(
                    value,
                    list
                ):

                    value = ", ".join(
                        str(item)
                        for item in value
                    )

                add(
                    f"{label}: {value}"
                )

            add()

    else:

        add(
            "No security findings discovered."
        )

    # --------------------------------------------------
    # IMPACT AND REMEDIATION
    # --------------------------------------------------

    add()
    add("IMPACT AND REMEDIATION")
    add("-" * 70)

    risk_assessments = state.get(
        "risk_assessments",
        []
    )

    if risk_assessments:

        for index, risk in enumerate(
            risk_assessments,
            1
        ):

            category = str(
                risk.get(
                    "category",
                    "unknown"
                )
            ).upper()

            add(
                f"Finding {index}"
            )

            add(
                f"Category: {category}"
            )

            add(
                "Impact: "
                f"{risk.get('impact', 'Not available')}"
            )

            add(
                "Recommended Remediation: "
                f"{risk.get('remediation', 'Not available')}"
            )

            add()

    else:

        add(
            "No impact or remediation information available."
        )

    # --------------------------------------------------
    # ADAPTIVE CHAINS
    # --------------------------------------------------

    add()
    add("ADAPTIVE CHAINS")
    add("-" * 70)

    chains = state.get(
        "chain_history",
        []
    )

    if chains:

        for index, chain in enumerate(
            chains,
            1
        ):

            chain_name = ""

            if isinstance(
                chain,
                dict
            ):

                chain_name = chain.get(
                    "chain",
                    ""
                )

            add(
                f"Chain {index}"
            )

            add(
                "Chain Type: "
                f"{chain_name or 'Adaptive Chain'}"
            )

            add(
                "Source: "
                f"{extract_chain_source(chain)}"
            )

            add(
                "Next Module: "
                f"{extract_chain_destination(chain)}"
            )

            reason = extract_chain_reason(
                chain
            )

            if reason:

                add(
                    f"Reason: {reason}"
                )

            add(
                "Status: Completed"
            )

            add()

    else:

        add(
            "No adaptive chains completed."
        )

    # --------------------------------------------------
    # LLM DECISION HISTORY
    # --------------------------------------------------

    add()
    add("LLM DECISION HISTORY")
    add("-" * 70)

    decision_history = state.get(
        "decision_history",
        []
    )

    if decision_history:

        for index, decision in enumerate(
            decision_history,
            1
        ):

            if isinstance(
                decision,
                dict
            ):

                step = decision.get(
                    "step",
                    index
                )

                action = extract_decision_action(
                    decision
                )

                reason = extract_decision_reason(
                    decision
                )

                add(
                    f"Step {step}"
                )

                add(
                    f"Action: {action}"
                )

                if reason:

                    add(
                        f"Reason: {reason}"
                    )

                add()

            else:

                add(
                    f"{index}. {decision}"
                )

    else:

        decision_log = state.get(
            "decision_log",
            []
        )

        if decision_log:

            for entry in decision_log:

                add(
                    f"- {entry}"
                )

        else:

            add(
                "No decision history available."
            )

    # --------------------------------------------------
    # END
    # --------------------------------------------------

    add("=" * 70)
    add("END OF REPORT")
    add("=" * 70)

    return "\n".join(lines)