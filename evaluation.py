"""
Baseline vs Adaptive evaluation.

Runs the same assessment twice against the authorized local target:
  - BASELINE : adaptive chaining DISABLED -> a traditional linear scanner that
               runs the core modules in a fixed order and never reaches IDOR.
  - ADAPTIVE : adaptive chaining ENABLED  -> the attack graph + LLM select the
               next action and a verified SQLi auth-bypass chains into IDOR.

The contrast (adaptive discovers cross-user access that the baseline misses)
substantiates the project's core claim.
"""

from agent import run_agent
from modules.risk_engine import is_vulnerable

TARGET = "http://localhost:3000"


def get_summary(state):
    modules = state.get("modules_run", [])
    findings = state.get("findings", [])
    metrics = state.get("metrics", {})
    idor_state = state.get("idor_state", {}) or {}

    confirmed = sum(1 for f in findings if isinstance(f, dict) and is_vulnerable(f))

    return {
        "modules_executed": len(modules),
        "workflow_steps": state.get("step_count", 0),
        "findings": len(findings),
        "confirmed_vulnerabilities": confirmed,
        "chains_triggered": metrics.get("chains_triggered", 0),
        "chains_completed": metrics.get("chains_completed", 0),
        "idor_executed": "idor_check" in modules,
        "unauthorized_access": len(idor_state.get("successful_targets", [])),
        "modules": modules,
        "chains": state.get("chain_history", []),
    }


def print_summary(title, s):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)
    print(f"Modules executed:        {s['modules_executed']}")
    print(f"Workflow steps:          {s['workflow_steps']}")
    print(f"Findings:                {s['findings']}")
    print(f"Confirmed vulnerabilities:{s['confirmed_vulnerabilities']}")
    print(f"Chains triggered:        {s['chains_triggered']}")
    print(f"Chains completed:        {s['chains_completed']}")
    print(f"IDOR executed:           {'YES' if s['idor_executed'] else 'NO'}")
    print(f"Unauthorized access:     {s['unauthorized_access']}")
    print(f"Modules: {s['modules']}")
    if s["chains"]:
        print("\nChains:")
        for ch in s["chains"]:
            if isinstance(ch, dict) and ch.get("next_module"):
                print(f"  {ch.get('source')} -> {ch.get('next_module')} [{ch.get('status')}]")
    else:
        print("\nChains: None")


def compare_results(baseline, adaptive):
    print("\n" + "=" * 60)
    print("BASELINE VS ADAPTIVE")
    print("=" * 60)
    rows = [
        ("Modules Executed", "modules_executed"),
        ("Workflow Steps", "workflow_steps"),
        ("Findings", "findings"),
        ("Confirmed Vulnerabilities", "confirmed_vulnerabilities"),
        ("Chains Triggered", "chains_triggered"),
        ("Chains Completed", "chains_completed"),
        ("IDOR Executed", "idor_executed"),
        ("Unauthorized Access", "unauthorized_access"),
    ]
    print(f"{'Metric':<28}{'Baseline':<14}{'Adaptive':<14}")
    print("-" * 56)
    for label, key in rows:
        b, a = baseline[key], adaptive[key]
        if isinstance(b, bool):
            b, a = ("YES" if b else "NO"), ("YES" if a else "NO")
        print(f"{label:<28}{str(b):<14}{str(a):<14}")

    if adaptive["idor_executed"] and not baseline["idor_executed"]:
        print(
            "\nConclusion: adaptive chaining recognized that SQL injection "
            "produced an authenticated session and expanded the assessment to "
            "IDOR, confirming unauthorized cross-user access that the linear "
            "baseline never tested."
        )


def main():
    print("=" * 60)
    print("VAPT ADAPTIVE AGENT EVALUATION")
    print("=" * 60)
    print(f"\nTarget: {TARGET}")

    print("\nRunning BASELINE assessment (chaining disabled)...")
    baseline = get_summary(run_agent(TARGET, chaining_enabled=False))
    print_summary("BASELINE RESULTS", baseline)

    print("\nRunning ADAPTIVE assessment (chaining enabled)...")
    adaptive = get_summary(run_agent(TARGET, chaining_enabled=True))
    print_summary("ADAPTIVE RESULTS", adaptive)

    compare_results(baseline, adaptive)
    print("\n" + "=" * 60)
    print("Evaluation complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()
