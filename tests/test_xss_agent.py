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

from agents.xss_agent import (
    choose_next_target,
    test_selected_target
)

from tools.xss_tools import get_xss_targets


state = initial_state(
    "http://localhost:3000"
)


discovered_targets = get_xss_targets(
    state
)


state["xss_state"][
    "discovered_targets"
] = discovered_targets


print()
print("XSS TARGET DISCOVERY")
print("=" * 40)

for target in discovered_targets:
    print(target)


while True:

    decision = choose_next_target(
        state
    )

    print()
    print("XSS AGENT DECISION")
    print("=" * 40)
    print(decision)

    if decision["action"] == "finish":

        print()
        print("XSS AGENT FINISHED")
        print("=" * 40)
        print(decision["reason"])

        break

    target_index = decision[
        "target_index"
    ]

    target = state["xss_state"][
        "discovered_targets"
    ][target_index]

    test_selected_target(
        state,
        target,
        decision["reason"]
    )


print()
print("FINAL XSS AGENT STATE")
print("=" * 40)

print(
    "Tested:",
    state["xss_state"][
        "tested_targets"
    ]
)

print(
    "Successful:",
    state["xss_state"][
        "successful_targets"
    ]
)

print(
    "Remaining:",
    state["xss_state"][
        "remaining_targets"
    ]
)

print(
    "Observations:",
    len(
        state["xss_state"][
            "observations"
        ]
    )
)

print(
    "Iterations:",
    state["xss_state"][
        "iteration"
    ]
)