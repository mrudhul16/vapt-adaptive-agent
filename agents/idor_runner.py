from agents.idor_agent import (
    choose_next_target,
    update_idor_state
)

from tools.idor_tools import (
    discover_idor_targets,
    execute_idor_test
)


MAX_ITERATIONS = 20


def run_idor_specialist(state):

    idor_state = state["idor_state"]

    print()
    print("=" * 60)
    print("IDOR SPECIALIST AGENT")
    print("=" * 60)

    targets = discover_idor_targets(state)

    idor_state["discovered_targets"] = targets

    idor_state["remaining_targets"] = (
        targets.copy()
    )

    print()
    print("DISCOVERED IDOR TARGETS")
    print("-" * 40)

    for index, target in enumerate(targets):
        print(index, target)

    if not targets:

        idor_state["completed"] = True

        return {
            "finding_type": "idor",

            "data": {
                "vulnerable": False,

                "detail": (
                    "No IDOR targets discovered."
                ),

                "specialist": True
            },

            "chain_trigger": False,

            "chain_data": None
        }

    for _ in range(MAX_ITERATIONS):

        if not idor_state["remaining_targets"]:
            break

        decision = choose_next_target(state)

        print()
        print("GPT-OSS IDOR DECISION")
        print("-" * 40)

        print(decision)

        if decision.get("action") == "finish":
            break

        target_index = decision.get(
            "target_index"
        )

        if target_index is None:
            break

        discovered_targets = (
            idor_state[
                "discovered_targets"
            ]
        )

        if (
            not isinstance(
                target_index,
                int
            )
            or target_index < 0
            or target_index >= len(
                discovered_targets
            )
        ):

            print(
                "Invalid IDOR target selected."
            )

            break

        target = (
            discovered_targets[
                target_index
            ]
        )

        if target not in (
            idor_state[
                "remaining_targets"
            ]
        ):

            print(
                "GPT-OSS selected an "
                "already tested target."
            )

            break

        reason = decision.get(
            "reason",
            "Selected by GPT-OSS."
        )

        idor_state[
            "current_target"
        ] = target

        result = execute_idor_test(
            state,
            target
        )

        print()
        print("IDOR TEST RESULT")
        print("-" * 40)

        safe_data = {}

        for key, value in result.get(
            "data",
            {}
        ).items():

            if key in {
                "token",
                "auth_token",
                "authenticated_session",
                "storage",
                "response"
            }:
                continue

            safe_data[key] = value

        safe_result = {
            "success": result.get(
                "success",
                False
            ),
            "data": safe_data
        }

        print(safe_result)

        update_idor_state(
            state,
            target,
            result,
            reason
        )

    idor_state["completed"] = True

    successful_targets = (
        idor_state[
            "successful_targets"
        ]
    )

    tested_targets = (
        idor_state[
            "tested_targets"
        ]
    )

    vulnerable = (
        len(successful_targets) > 0
    )

    unauthorized_count = (
        len(successful_targets)
    )

    print()
    print("=" * 60)
    print("IDOR SPECIALIST COMPLETE")
    print("=" * 60)

    print(
        "Targets discovered:",
        len(
            idor_state[
                "discovered_targets"
            ]
        )
    )

    print(
        "Targets tested:",
        len(tested_targets)
    )

    print(
        "Successful targets:",
        unauthorized_count
    )

    print(
        "Remaining targets:",
        len(
            idor_state[
                "remaining_targets"
            ]
        )
    )

    if vulnerable:

        print()

        print(
            "IDOR CONFIRMED:",
            unauthorized_count,
            "unauthorized resource(s) accessible."
        )

    else:

        print()

        print(
            "NO IDOR CONFIRMED"
        )

    if vulnerable:

        detail = (
            f"IDOR confirmed: "
            f"{unauthorized_count} "
            f"unauthorized resource(s) "
            f"were accessible to the "
            f"authenticated user."
        )

        impact = (
            "An authenticated user may "
            "access resources belonging "
            "to other users."
        )

    else:

        detail = (
            f"IDOR testing completed "
            f"across "
            f"{len(tested_targets)} "
            f"targets. "
            f"No unauthorized resource "
            f"access was confirmed."
        )

        impact = (
            "No unauthorized resource "
            "access was confirmed."
        )

    return {
        "finding_type": "idor",

        "data": {

            "vulnerable": vulnerable,

            "detail": detail,

            "impact": impact,

            "unauthorized_resource_count": (
                unauthorized_count
            ),

            "successful_targets": (
                successful_targets
            ),

            "tested_targets": (
                tested_targets
            ),

            "authenticated": bool(
                idor_state.get(
                    "authenticated_session"
                )
            ),

            "specialist": True
        },

        "chain_trigger": False,

        "chain_data": None
    }