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
    test_selected_target as run_target
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

    # choose_next_target now returns an index into the expanded candidate pool,
    # not the raw reconnaissance set.
    target = state["xss_state"][
        "candidate_pool"
    ][target_index]

    run_target(
        state,
        target,
        decision["reason"]
    )


print()
print("FINAL XSS AGENT STATE")
print("=" * 40)

print(
    "Tested:",
    len(state["xss_state"]["tested_targets"])
)

print(
    "Successful (Suspected):",
    len(state["xss_state"]["successful_targets"])
)

print(
    "Confirmed:",
    len(state["xss_state"].get("confirmed_vulnerabilities", []))
)

print(
    "Inconclusive:",
    len(state["xss_state"].get("inconclusive_targets", []))
)

print(
    "Remaining:",
    len(state["xss_state"]["remaining_targets"])
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