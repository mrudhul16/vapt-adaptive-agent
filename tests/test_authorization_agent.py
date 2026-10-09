from agents.authorization_agent import (
    initialize_authorization_state,
    choose_authorization_target,
    update_authorization_state,
    finish_authorization_state,
)

from tools.authorization_tools import (
    execute_authorization_test,
)


RECON_STATE = {
    "attack_surface": {
        "authorization": [
            {
                "url": "http://localhost:3000/rest/admin",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/profile",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/accounting",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/address/saved",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/address/select",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/address/create",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/address/edit/",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/api/Addresss",
                "type": "endpoint",
            },
            {
                "url": "http://localhost:3000/api/Users",
                "type": "endpoint",
            },
        ],
        "user_endpoints": [],
    }
}


def main():
    print()
    print("=" * 70)
    print("AUTHORIZATION SPECIALIST STANDALONE TEST")
    print("=" * 70)

    state = initialize_authorization_state(
        RECON_STATE
    )

    print()
    print("DISCOVERED TARGETS")
    print("-" * 40)

    for index, target in enumerate(
        state["discovered_targets"]
    ):
        print(index, target)

    max_tests = 10
    tests = 0

    while (
        state["remaining_targets"]
        and tests < max_tests
    ):
        decision = choose_authorization_target(
            state
        )

        print()
        print("GPT-OSS AUTHORIZATION BATCH DECISION")
        print("-" * 40)
        print(decision)

        if decision["action"] == "finish":
            break

        targets = decision.get("targets", [])

        if not targets:
            break

        for target in targets:
            if tests >= max_tests:
                break

            print()
            print("AUTHORIZATION TARGET SELECTED")
            print("-" * 40)
            print(target)

            result = execute_authorization_test(
                state,
                target
            )

            print()
            print("AUTHORIZATION TEST RESULT")
            print("-" * 40)
            print(result)

            state = update_authorization_state(
                state,
                target,
                result,
                decision.get(
                    "reason",
                    "Authorization target selected."
                ),
            )

            tests += 1

    state = finish_authorization_state(
        state
    )

    print()
    print("=" * 70)
    print("AUTHORIZATION SPECIALIST COMPLETE")
    print("=" * 70)

    print(
        "Targets discovered:",
        len(
            state["discovered_targets"]
        )
    )

    print(
        "Targets tested:",
        len(
            state["tested_targets"]
        )
    )

    print(
        "Targets remaining:",
        len(
            state["remaining_targets"]
        )
    )

    print(
        "Findings:",
        len(
            state.get("findings", [])
        )
    )

    print(
        "Suspected targets:",
        len(
            state.get("successful_targets", [])
        )
    )

    print(
        "Confirmed targets:",
        len(
            state.get("confirmed_vulnerabilities", [])
        )
    )

    print(
        "Completed:",
        state["completed"]
    )


if __name__ == "__main__":
    main()