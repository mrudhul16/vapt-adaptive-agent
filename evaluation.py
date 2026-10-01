from agent import app
from state import initial_state


TARGET = "http://localhost:3000"


def run_assessment(chaining_enabled):

    state = initial_state(
        TARGET,
        chaining_enabled=chaining_enabled
    )

    final_state = app.invoke(state)

    return final_state


def get_summary(state):

    return {
        "modules_executed": len(
            state["modules_run"]
        ),

        "workflow_steps": state[
            "step_count"
        ],

        "findings": len(
            state["findings"]
        ),

        "chains_triggered": state[
            "metrics"
        ]["chains_triggered"],

        "chains_completed": state[
            "metrics"
        ]["chains_completed"],

        "modules": state[
            "modules_run"
        ],

        "chains": state[
            "chain_history"
        ]
    }


def print_summary(title, summary):

    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    print(
        f"Modules executed: "
        f"{summary['modules_executed']}"
    )

    print(
        f"Workflow steps: "
        f"{summary['workflow_steps']}"
    )

    print(
        f"Findings: "
        f"{summary['findings']}"
    )

    print(
        f"Chains triggered: "
        f"{summary['chains_triggered']}"
    )

    print(
        f"Chains completed: "
        f"{summary['chains_completed']}"
    )

    print(
        f"Modules: "
        f"{summary['modules']}"
    )

    if summary["chains"]:

        print("\nCompleted chains:")

        for chain in summary["chains"]:

            print(
                f"  {chain.get('trigger')} "
                f"→ "
                f"{chain.get('next_module')}"
            )

    else:

        print(
            "\nCompleted chains: None"
        )


def compare_results(baseline, adaptive):

    print("\n" + "=" * 60)
    print("BASELINE VS ADAPTIVE")
    print("=" * 60)

    metrics = [
        ("Modules Executed", "modules_executed"),
        ("Workflow Steps", "workflow_steps"),
        ("Findings", "findings"),
        ("Chains Triggered", "chains_triggered"),
        ("Chains Completed", "chains_completed")
    ]

    print(
        f"{'Metric':<25}"
        f"{'Baseline':<15}"
        f"{'Adaptive':<15}"
    )

    print("-" * 55)

    for label, key in metrics:

        print(
            f"{label:<25}"
            f"{baseline[key]:<15}"
            f"{adaptive[key]:<15}"
        )


def main():

    print("=" * 60)
    print("VAPT ADAPTIVE AGENT EVALUATION")
    print("=" * 60)

    print(
        f"\nTarget: {TARGET}"
    )

    print(
        "\nRunning baseline assessment..."
    )

    baseline_state = run_assessment(
        chaining_enabled=False
    )

    baseline = get_summary(
        baseline_state
    )

    print_summary(
        "BASELINE RESULTS",
        baseline
    )

    print(
        "\nRunning adaptive assessment..."
    )

    adaptive_state = run_assessment(
        chaining_enabled=True
    )

    adaptive = get_summary(
        adaptive_state
    )

    print_summary(
        "ADAPTIVE RESULTS",
        adaptive
    )

    compare_results(
        baseline,
        adaptive
    )

    print(
        "\n" + "=" * 60
    )

    print(
        "Evaluation complete."
    )

    print(
        "=" * 60
    )


if __name__ == "__main__":
    main()