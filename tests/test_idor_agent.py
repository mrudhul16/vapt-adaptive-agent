import sys
import os

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from state import initial_state

from agents.idor_agent import (
    choose_next_target,
    update_idor_state
)

from tools.idor_tools import (
    discover_idor_targets,
    discover_basket_ids,
    execute_idor_test
)

from tools.sqli_tools import (
    get_sqli_targets,
    execute_sqli_test
)


TARGET_URL = "http://localhost:3000"


state = initial_state(
    TARGET_URL
)


# --------------------------------------------------
# SQLi → IDOR AUTHENTICATION HANDOFF
# --------------------------------------------------

print()
print("SQLi → IDOR CHAIN")
print("=" * 40)

sqli_targets = get_sqli_targets(
    state
)

login_target = None

for target in sqli_targets:

    if target.get("type") == "login_form":

        login_target = target
        break


if login_target is None:

    print("NO LOGIN TARGET FOUND")
    sys.exit(0)


print()
print("SQLi TARGET")
print("=" * 40)
print(login_target)


sqli_result = execute_sqli_test(
    state,
    login_target
)


sqli_data = sqli_result.get(
    "data",
    {}
)


print()
print("SQLi RESULT")
print("=" * 40)

print(
    "Vulnerable:",
    sqli_data.get("vulnerable")
)

print(
    "Authenticated:",
    sqli_data.get("authenticated")
)

print(
    "Chain Trigger:",
    sqli_data.get("chain_trigger")
)


if not sqli_data.get(
    "chain_trigger"
):

    print()
    print("SQLi DID NOT PRODUCE AUTHENTICATED SESSION")
    sys.exit(0)


chain_data = sqli_data.get(
    "chain_data",
    {}
)


authenticated_session = (
    chain_data.get(
        "authenticated_session",
        {}
    )
)


if not authenticated_session.get(
    "token"
):

    print()
    print("NO AUTHENTICATED SESSION TOKEN")
    sys.exit(0)


# --------------------------------------------------
# PASS SESSION TO IDOR AGENT
# --------------------------------------------------

state[
    "idor_state"
][
    "authenticated_session"
] = authenticated_session


print()
print("AUTHENTICATED SESSION")
print("=" * 40)

print(
    "Token received:",
    bool(
        authenticated_session.get(
            "token"
        )
    )
)

print(
    "Token source:",
    chain_data.get(
        "auth_token_source"
    )
)


# --------------------------------------------------
# IDOR TARGET DISCOVERY
# --------------------------------------------------

print()
print("IDOR TARGET DISCOVERY")
print("=" * 40)


targets = discover_idor_targets(
    state
)


basket_targets = discover_basket_ids(
    state
)


for target in basket_targets:

    if target not in targets:

        targets.append(target)


state[
    "idor_state"
][
    "discovered_targets"
] = targets


state[
    "idor_state"
][
    "remaining_targets"
] = targets.copy()


for target in targets:

    print(target)


if not targets:

    print()
    print("NO IDOR TARGETS FOUND")
    print("=" * 40)

    sys.exit(0)


# --------------------------------------------------
# IDOR AGENT LOOP
# --------------------------------------------------

while True:

    decision = choose_next_target(
        state
    )

    print()
    print("IDOR AGENT BATCH DECISION")
    print("=" * 40)

    print(decision)


    if decision.get("action") == "finish":

        state[
            "idor_state"
        ][
            "completed"
        ] = True

        print()
        print("IDOR AGENT FINISHED")
        print("=" * 40)

        print(
            decision.get(
                "reason",
                "IDOR testing completed."
            )
        )

        break

    targets = decision.get("targets", [])

    if not targets:
        break

    for target in targets:
        print()
        print("IDOR TARGET SELECTED")
        print("=" * 40)

        print(target)

        result = execute_idor_test(
            state,
            target
        )

        print()
        print("IDOR TEST RESULT")
        print("=" * 40)

        safe_result = {
            "success": result.get(
                "success"
            ),
            "vulnerable": result.get(
                "data",
                {}
            ).get(
                "vulnerable"
            ),
            "status_code": result.get(
                "data",
                {}
            ).get(
                "status_code"
            ),
            "authenticated_request": result.get(
                "data",
                {}
            ).get(
                "authenticated_request"
            ),
            "unauthorized_access": result.get(
                "data",
                {}
            ).get(
                "unauthorized_access"
            ),
            "error": result.get(
                "data",
                {}
            ).get(
                "error"
            )
        }

        print(safe_result)

        update_idor_state(
            state,
            target,
            result,
            decision.get(
                "reason",
                "Selected by GPT-OSS."
            )
        )


# --------------------------------------------------
# FINAL STATE
# --------------------------------------------------

print()
print("FINAL IDOR AGENT STATE")
print("=" * 40)

print(
    "Tested:",
    state[
        "idor_state"
    ][
        "tested_targets"
    ]
)

print(
    "Successful:",
    state[
        "idor_state"
    ][
        "successful_targets"
    ]
)

print(
    "Remaining:",
    state[
        "idor_state"
    ][
        "remaining_targets"
    ]
)

print(
    "Observations:",
    len(
        state[
            "idor_state"
        ][
            "observations"
        ]
    )
)

print(
    "Iterations:",
    state[
        "idor_state"
    ][
        "iteration"
    ]
)

print(
    "Completed:",
    state[
        "idor_state"
    ][
        "completed"
    ]
)