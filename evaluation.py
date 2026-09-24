import sys
from agent import app
from state import initial_state

TARGET = "http://localhost:3000"

def evaluate_mode(mode_name, chaining_enabled):
    print(f"\n--- Running {mode_name} ---")
    try:
        state = initial_state(TARGET, chaining_enabled=chaining_enabled)
        result = app.invoke(state)
        
        modules = result.get("modules_run", [])
        steps = result.get("step_count", 0)
        findings = result.get("findings", [])
        decision_log = result.get("decision_log", [])
        
        vulnerabilities_confirmed = sum(
            1 for f in findings 
            if isinstance(f.get("data"), dict) and f["data"].get("vulnerable") is True
        )
        
        idor_executed = "idor" in modules or "idor_check" in modules
        
        return {
            "mode": mode_name,
            "modules_run": modules,
            "total_steps": steps,
            "total_findings": len(findings),
            "vulnerabilities_confirmed": vulnerabilities_confirmed,
            "idor_executed": idor_executed,
            "decision_log": decision_log,
            "success": True
        }
    except Exception as e:
        print(f"Error during {mode_name} evaluation: {e}")
        return {
            "mode": mode_name,
            "success": False,
            "error": str(e)
        }

def print_results(baseline, adaptive):
    print("============================================================")
    print("BASELINE vs ADAPTIVE EVALUATION")
    print("============================================================")
    
    for run in (baseline, adaptive):
        print(f"\n{run['mode']}")
        if not run['success']:
            print(f"FAILED: {run.get('error')}")
            continue
            
        print(f"Modules Run: {', '.join(run['modules_run'])}")
        print(f"Total Steps: {run['total_steps']}")
        print(f"Total Findings: {run['total_findings']}")
        print(f"Vulnerabilities Confirmed: {run['vulnerabilities_confirmed']}")
        print(f"IDOR Executed: {'YES' if run['idor_executed'] else 'NO'}")
        
    print("\n------------------------------------------------------------")
    print("BEHAVIORAL DIFFERENCE")
    print("------------------------------------------------------------")
    
    if not baseline['success'] or not adaptive['success']:
        print("Cannot compare due to failed run.")
        return
        
    b_modules = set(baseline['modules_run'])
    a_modules = set(adaptive['modules_run'])
    extra_modules = a_modules - b_modules
    
    adaptive_extra_steps = adaptive['total_steps'] - baseline['total_steps']
    adaptive_extra_modules = len(adaptive['modules_run']) - len(baseline['modules_run'])
    
    if extra_modules:
        print(f"Modules executed ONLY in adaptive mode: {', '.join(extra_modules)}")
    else:
        print("No additional modules executed in adaptive mode.")
        
    print(f"\nAdaptive extra modules count: {adaptive_extra_modules}")
    print(f"Adaptive extra steps count: {adaptive_extra_steps}")
    
    chains = [entry for entry in adaptive['decision_log'] if "CHAINED" in entry or "chained" in entry.lower()]
    if chains:
        print("\nRelevant Adaptive Decision Log Entries:")
        for c in chains:
            print(f"- {c}")
            
    if adaptive['idor_executed'] and not baseline['idor_executed']:
        print("\nAdaptive chaining caused IDOR to be executed after the preceding module produced an authenticated session.")
        
    print("\nMetric                  Baseline       Adaptive")
    print("-" * 55)
    
    def pad(val, width=15):
        return str(val).ljust(width)
        
    metrics = [
        ("Modules Run", len(baseline['modules_run']), len(adaptive['modules_run'])),
        ("Total Steps", baseline['total_steps'], adaptive['total_steps']),
        ("Total Findings", baseline['total_findings'], adaptive['total_findings']),
        ("IDOR Executed", "YES" if baseline['idor_executed'] else "NO", "YES" if adaptive['idor_executed'] else "NO"),
        ("Vulnerabilities", baseline['vulnerabilities_confirmed'], adaptive['vulnerabilities_confirmed'])
    ]
    
    for name, b_val, a_val in metrics:
        print(f"{name.ljust(24)}{pad(b_val)}{pad(a_val)}")

def main():
    print("Starting evaluation...")
    baseline_result = evaluate_mode("BASELINE (NO CHAINING)", False)
    adaptive_result = evaluate_mode("ADAPTIVE (WITH CHAINING)", True)
    
    print_results(baseline_result, adaptive_result)

if __name__ == "__main__":
    main()
