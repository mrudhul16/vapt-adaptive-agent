from agents.sqli_agent import (
    choose_next_target,
    test_selected_target
)

from tools.sqli_tools import get_sqli_targets


MAX_ITERATIONS = 20


def run_sqli_specialist(state):

    sqli_state = state["sqli_state"]

    print()
    print("=" * 60)
    print("SQLi SPECIALIST AGENT")
    print("=" * 60)

    targets = get_sqli_targets(state)

    sqli_state["discovered_targets"] = targets
    sqli_state["remaining_targets"] = targets.copy()

    print()
    print("DISCOVERED SQLi TARGETS")
    print("-" * 40)

    for index, target in enumerate(targets):
        print(index, target)

    if not targets:

        sqli_state["completed"] = True

        return {
            "finding_type": "sqli",
            "data": {
                "vulnerable": False,
                "detail": (
                    "No SQL injection targets discovered."
                ),
                "specialist": True
            },
            "chain_trigger": False,
            "chain_data": None
        }

    chain_trigger = False
    chain_data = None
    bypass_verified = False

    for _ in range(MAX_ITERATIONS):

        if not sqli_state["remaining_targets"]:
            break

        decision = choose_next_target(state)

        print()
        print("GPT-OSS SQLi DECISION")
        print("-" * 40)
        print(decision)

        if decision.get("action") == "finish":
            break

        target_index = decision.get("target_index")

        if target_index is None:
            break

        discovered_targets = (
            sqli_state["discovered_targets"]
        )

        if (
            not isinstance(target_index, int)
            or target_index < 0
            or target_index >= len(discovered_targets)
        ):
            print(
                "Invalid target selected. "
                "Stopping SQLi specialist."
            )
            break

        target = discovered_targets[target_index]

        if target not in sqli_state["remaining_targets"]:
            print(
                "GPT-OSS selected an already tested target. "
                "Stopping."
            )
            break

        reason = decision.get(
            "reason",
            "Selected by GPT-OSS."
        )

        result = test_selected_target(
            state,
            target,
            reason
        )

        result_data = result.get(
            "data",
            {}
        )

        if result_data.get("authentication_bypass_verified") is True:
            bypass_verified = True

        if result_data.get("chain_trigger") is True:
            current_chain_data = result_data.get("chain_data")
            if current_chain_data:
                if current_chain_data.get("chain") == "sqli_to_idor":
                    current_chain_data["next_module"] = "idor_check"
                
                chain_trigger = True
                chain_data = current_chain_data
                print("[SQLI RUNNER] Verified chain trigger; prioritizing IDOR.")
                break

    sqli_state["completed"] = True

    successful_targets = sqli_state["successful_targets"]
    confirmed_vulnerabilities = sqli_state.get("confirmed_vulnerabilities", [])

    print()
    print("=" * 60)
    print("SQLi SPECIALIST COMPLETE")
    print("=" * 60)

    print("Targets discovered:", len(sqli_state["discovered_targets"]))
    print("Targets tested:", len(sqli_state["tested_targets"]))
    print("Successful targets:", len(successful_targets))
    print("Confirmed vulnerabilities:", len(confirmed_vulnerabilities))
    print("Chain triggered:", chain_trigger)

    if chain_data:
        print("Chain:", chain_data.get("chain"))
        print("Next module:", chain_data.get("next_module"))

    return {
        "finding_type": "sqli",
        "data": {
            "vulnerable": len(confirmed_vulnerabilities) > 0 or bypass_verified,
            "confirmed": len(confirmed_vulnerabilities) > 0,
            "authentication_bypass_verified": bypass_verified,
            "detail": f"SQL injection testing completed across {len(sqli_state['tested_targets'])} targets.",
            "successful_targets": successful_targets,
            "confirmed_vulnerabilities": confirmed_vulnerabilities,
            "tested_targets": sqli_state["tested_targets"],
            "observations": sqli_state["observations"],
            "authenticated": chain_data.get("authenticated", False) if chain_data else False,
            "specialist": True
        },
        "chain_trigger": chain_trigger,
        "chain_data": chain_data
    }