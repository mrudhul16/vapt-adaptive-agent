"""
Module 6: Reporting
"""


def generate_report(state) -> str:
    lines = []
    lines.append("=" * 60)
    lines.append(f"SECURITY ASSESSMENT REPORT — {state['target_url']}")
    lines.append("=" * 60)

    lines.append(f"\nModules run: {', '.join(state['modules_run'])}")
    lines.append(f"Total steps taken: {state['step_count']}")

    lines.append("\n--- FINDINGS ---")
    if not state["findings"]:
        lines.append("No findings recorded.")
    for f in state["findings"]:
        lines.append(f"  - [{f['finding_type']}] {f['data']}")

    lines.append("\n--- REASONING TRAIL (why each action was taken) ---")
    for entry in state["decision_log"]:
        lines.append(f"  - {entry}")

    return "\n".join(lines)