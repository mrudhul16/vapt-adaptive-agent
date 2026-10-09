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

from agents.sqli_agent import (
    choose_next_target,
    test_selected_target as _test_selected_target
)

from tools.sqli_tools import get_sqli_targets


state = initial_state(
    "http://localhost:3000"
)


discovered_targets = get_sqli_targets(
    state
)


state["sqli_state"][
    "discovered_targets"
] = discovered_targets

state["sqli_state"][
    "remaining_targets"
] = discovered_targets.copy()


print()
print("SQLI TARGET DISCOVERY")
print("=" * 40)

for target in discovered_targets:

    print(target)


if not discovered_targets:

    print()
    print("NO SQLI TARGETS FOUND")
    print("=" * 40)

    sys.exit(0)


while True:

    decision = choose_next_target(
        state
    )

    print()
    print("SQLI AGENT DECISION")
    print("=" * 40)
    print(decision)

    if decision["action"] == "finish":

        state["sqli_state"][
            "completed"
        ] = True

        print()
        print("SQLI AGENT FINISHED")
        print("=" * 40)
        print(decision["reason"])

        break

    target_index = decision[
        "target_index"
    ]

    if (
        target_index is None
        or target_index < 0
        or target_index >= len(
            state["sqli_state"][
                "discovered_targets"
            ]
        )
    ):

        print()
        print("INVALID TARGET INDEX")
        print("=" * 40)

        break

    target = state["sqli_state"][
        "discovered_targets"
    ][target_index]

    _test_selected_target(
        state,
        target,
        decision["reason"]
    )


print()
print("FINAL SQLI AGENT STATE")
print("=" * 40)

print(
    "Tested:",
    state["sqli_state"][
        "tested_targets"
    ]
)

print(
    "Successful:",
    state["sqli_state"][
        "successful_targets"
    ]
)

print(
    "Remaining:",
    state["sqli_state"][
        "remaining_targets"
    ]
)

print(
    "Observations:",
    len(
        state["sqli_state"][
            "observations"
        ]
    )
)

print(
    "Iterations:",
    state["sqli_state"][
        "iteration"
    ]
)

print(
    "Completed:",
    state["sqli_state"][
        "completed"
    ]
)