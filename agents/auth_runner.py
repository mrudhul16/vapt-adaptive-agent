from agents.auth_agent import (
    initialize_auth_state,
    choose_auth_target,
    update_auth_state,
    finish_auth_state
)

from tools.auth_tools import execute_auth_test


MAX_AUTH_TESTS = 10


def run_auth_specialist(recon_state):

    print("\n" + "=" * 70)
    print("AUTHENTICATION SPECIALIST AGENT")
    print("=" * 70)

    # ---------------------------------------------------------
    # FIX:
    # Recon specialist returns a result containing the
    # reconnaissance data inside "data".
    #
    # AUTH needs the actual reconnaissance data/state.
    # ---------------------------------------------------------

    if isinstance(recon_state, dict):

        if isinstance(
            recon_state.get("data"),
            dict
        ):
            auth_source = recon_state["data"]

        else:
            auth_source = recon_state

    else:
        auth_source = {}

    # ---------------------------------------------------------
    # Make sure authentication targets are available
    # from the Recon attack surface.
    # ---------------------------------------------------------

    attack_surface = auth_source.get(
        "attack_surface",
        {}
    )

    authentication_targets = attack_surface.get(
        "authentication",
        []
    )

    # ---------------------------------------------------------
    # Fallback to auth_endpoints if attack_surface is missing.
    # ---------------------------------------------------------

    if not authentication_targets:

        auth_endpoints = auth_source.get(
            "auth_endpoints",
            []
        )

        authentication_targets = [
            {
                "url": url,
                "type": "endpoint"
            }
            for url in auth_endpoints
            if isinstance(url, str)
        ]

    # ---------------------------------------------------------
    # Build a clean Recon state specifically for AUTH.
    # ---------------------------------------------------------

    auth_recon_state = {
        "attack_surface": {
            "auth_endpoints": authentication_targets
        },
        "auth_endpoints": [
            target.get("url")
            for target in authentication_targets
            if isinstance(target, dict)
            and target.get("url")
        ],
        "discovered_targets": authentication_targets,
        "endpoints": [
            target.get("url")
            for target in authentication_targets
            if isinstance(target, dict)
            and target.get("url")
        ],
        # Emails discovered elsewhere (seeded by the orchestrator) let the
        # user-enumeration probe differentiate real accounts from fake ones.
        "discovered_emails": auth_source.get("discovered_emails", []),
    }

    # ---------------------------------------------------------
    # Initialize AUTH specialist state.
    # ---------------------------------------------------------

    auth_state = initialize_auth_state(
        auth_recon_state
    )

    print("\nDISCOVERED AUTHENTICATION TARGETS")

    for index, target in enumerate(
        auth_state["discovered_targets"]
    ):

        print(
            index,
            target["url"]
        )

    test_count = 0
    successful_targets = 0

    while (
        auth_state["remaining_targets"]
        and test_count < MAX_AUTH_TESTS
    ):

        decision = choose_auth_target(
            auth_state
        )

        if decision["action"] == "finish":
            break

        # -----------------------------------------------------
        # Use the actual target returned by the AUTH agent.
        # -----------------------------------------------------

        target = decision.get(
            "target"
        )

        if not target:

            print(
                "\nAUTH AGENT ERROR: "
                "No target returned"
            )

            break

        target_url = target.get(
            "url",
            ""
        )

        print("\nAUTH TARGET SELECTED")
        print(target_url)

        try:

            result = execute_auth_test(
                auth_recon_state,
                target
            )

        except Exception as e:

            result = {
                "success": False,
                "status": "error",
                "error": type(e).__name__
            }

        result_status = result.get(
            "status",
            result.get(
                "message",
                "completed"
            )
        )

        print(
            "RESULT:",
            result_status
        )

        result_data = result.get("data") if isinstance(result, dict) else None
        if isinstance(result_data, dict) and result_data.get("vulnerable") is True:
            successful_targets += 1

        update_auth_state(
            auth_state,
            target,
            result,
            decision.get(
                "reason",
                ""
            )
        )

        test_count += 1

    finish_auth_state(
        auth_state
    )

    print(
        "\nAUTHENTICATION SPECIALIST COMPLETE"
    )

    print(
        "Targets discovered:",
        len(
            auth_state[
                "discovered_targets"
            ]
        )
    )

    print(
        "Targets tested:",
        len(
            auth_state[
                "tested_targets"
            ]
        )
    )

    print(
        "Successful targets:",
        successful_targets
    )

    print(
        "Remaining targets:",
        len(
            auth_state[
                "remaining_targets"
            ]
        )
    )

    print(
        "Session Created by Module:",
        auth_state.get("session_created_by_module", False)
    )

    auth_findings = auth_state.get("findings", [])

    return {
        "module": "authentication",

        # Surface auth weaknesses to the orchestrator/dashboard.
        "vulnerable": len(auth_findings) > 0,

        "state": auth_state,

        "targets_discovered": len(
            auth_state[
                "discovered_targets"
            ]
        ),

        "targets_tested": len(
            auth_state[
                "tested_targets"
            ]
        ),

        "remaining_targets": len(
            auth_state[
                "remaining_targets"
            ]
        ),

        "authenticated": auth_state.get(
            "session_created_by_module", False
        ),

        "findings": auth_findings,

        "data": {
            "vulnerable": len(auth_findings) > 0,
            "findings": auth_findings,
            "successful_targets": auth_findings,
            "detail": (
                f"Authentication analysis completed across "
                f"{len(auth_state.get('tested_targets', []))} endpoints; "
                f"{len(auth_findings)} weakness(es) flagged."
            ),
        },

        "observations": auth_state.get(
            "observations",
            []
        )
    }