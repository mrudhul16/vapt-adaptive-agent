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
        return [redact_sensitive_data(item) for item in value]

    return value


def generate_report(state) -> str:
    lines = []

    lines.append("=" * 70)
    lines.append("VAPT ADAPTIVE AGENT - SECURITY ASSESSMENT REPORT")
    lines.append("=" * 70)

    lines.append("")
    lines.append("ASSESSMENT OVERVIEW")
    lines.append("-" * 70)
    lines.append(f"Target: {state.get('target_url', 'N/A')}")
    lines.append(
        f"Assessment Started: {state.get('assessment_start_time', 'N/A')}"
    )
    lines.append(
        f"Adaptive Chaining: {'Enabled' if state.get('chaining_enabled') else 'Disabled'}"
    )

    lines.append("")
    lines.append("EXECUTION SUMMARY")
    lines.append("-" * 70)

    metrics = state.get("metrics", {})

    lines.append(
        f"Modules Executed: {metrics.get('modules_executed', len(state.get('modules_run', [])))}"
    )
    lines.append(
        f"Workflow Steps: {metrics.get('workflow_steps', state.get('step_count', 0))}"
    )
    lines.append(
        f"Findings Discovered: {metrics.get('findings_discovered', len(state.get('findings', [])))}"
    )
    lines.append(
        f"Chains Triggered: {metrics.get('chains_triggered', 0)}"
    )
    lines.append(
        f"Chains Completed: {metrics.get('chains_completed', 0)}"
    )

    lines.append("")
    lines.append("MODULES EXECUTED")
    lines.append("-" * 70)

    for index, module in enumerate(state.get("modules_run", []), 1):
        lines.append(f"{index}. {module}")

    lines.append("")
    lines.append("RECONNAISSANCE")
    lines.append("-" * 70)

    tech_stack = state.get("tech_stack", {})

    if tech_stack:
        for key, value in tech_stack.items():
            lines.append(f"{key}: {value}")
    else:
        lines.append("No reconnaissance information available.")

    lines.append("")
    lines.append("DISCOVERED RESOURCES")
    lines.append("-" * 70)

    pages = state.get("pages", [])

    if pages:
        for page in pages:
            lines.append(f"- {page}")
    else:
        lines.append("No resources discovered.")

    lines.append("")
    lines.append("FINDINGS")
    lines.append("-" * 70)

    findings = state.get("findings", [])

    if findings:
        for index, finding in enumerate(findings, 1):
            safe_finding = redact_sensitive_data(finding)

            lines.append(f"Finding {index}")

            finding_type = safe_finding.get(
                "finding_type",
                safe_finding.get("category", "unknown")
            )

            lines.append(f"Category: {finding_type}")

            data = safe_finding.get("data")

            if data:
                lines.append("Details:")

                if isinstance(data, dict):
                    for key, value in data.items():
                        lines.append(f"  {key}: {value}")
                else:
                    lines.append(f"  {data}")

            lines.append("")

    else:
        lines.append("No findings discovered.")

    lines.append("")
    lines.append("IMPACT AND REMEDIATION")
    lines.append("-" * 70)

    risk_assessments = state.get("risk_assessments", [])

    if risk_assessments:
        for index, risk in enumerate(risk_assessments, 1):
            lines.append(f"Finding {index}")
            lines.append(
                f"Category: {risk.get('category', 'unknown').upper()}"
            )
            lines.append(
                f"Impact: {risk.get('impact', 'Not available')}"
            )
            lines.append(
                f"Recommended Remediation: {risk.get('remediation', 'Not available')}"
            )
            lines.append("")
    else:
        lines.append("No impact or remediation information available.")

    lines.append("")
    lines.append("ADAPTIVE CHAINS")
    lines.append("-" * 70)

    chains = state.get("chain_history", [])

    if chains:
        for index, chain in enumerate(chains, 1):
            lines.append(f"Chain {index}")

            source = (
                chain.get("source")
                or chain.get("trigger")
                or chain.get("finding")
                or "Finding"
            )

            next_module = chain.get(
                "next_module",
                chain.get("destination", "unknown")
            )

            reason = chain.get("reason", "")

            lines.append(f"Source: {source}")
            lines.append(f"Next Module: {next_module}")

            if reason:
                lines.append(f"Reason: {reason}")

            lines.append("Status: Completed")
            lines.append("")

    else:
        lines.append("No adaptive chains completed.")

    lines.append("")
    lines.append("LLM DECISION HISTORY")
    lines.append("-" * 70)

    decision_history = state.get("decision_history", [])

    if decision_history:
        for index, decision in enumerate(decision_history, 1):
            if isinstance(decision, dict):
                step = decision.get("step", index)
                action = decision.get("action", "unknown")
                reason = decision.get("reason", "")

                lines.append(f"Step {step}")
                lines.append(f"Action: {action}")

                if reason:
                    lines.append(f"Reason: {reason}")

                lines.append("")
            else:
                lines.append(f"{index}. {decision}")

    else:
        decision_log = state.get("decision_log", [])

        if decision_log:
            for entry in decision_log:
                lines.append(f"- {entry}")
        else:
            lines.append("No decision history available.")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)