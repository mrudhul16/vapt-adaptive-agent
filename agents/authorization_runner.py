from agents.authorization_agent import (
    initialize_authorization_state,
    choose_authorization_target,
    update_authorization_state,
    finish_authorization_state,
    sanitize_authorization_result,
)

from tools.authorization_tools import execute_authorization_test


MAX_AUTHORIZATION_TESTS = 10


def extract_authenticated_session(recon_result):
    if not isinstance(recon_result, dict):
        return None

    possible_sources = [
        recon_result,
        recon_result.get("data", {}),
    ]

    for source in possible_sources:
        if not isinstance(source, dict):
            continue

        session = source.get("authenticated_session")

        if isinstance(session, dict):
            return session

        session = source.get("auth_session")

        if isinstance(session, dict):
            return session

        session = source.get("session")

        if isinstance(session, dict):
            return session

    return None


def run_authorization_specialist(
    recon_result,
    authenticated_session=None,
):
    if not isinstance(recon_result, dict):
        raise ValueError(
            "Invalid Recon result supplied to Authorization specialist."
        )

    recon_data = recon_result.get(
        "data",
        recon_result
    )

    if not isinstance(recon_data, dict):
        raise ValueError(
            "Recon result data is invalid."
        )

    if authenticated_session is None:
        authenticated_session = extract_authenticated_session(
            recon_result
        )

    authz_state = initialize_authorization_state(
        recon_data
    )

    authenticated_available = isinstance(
        authenticated_session,
        dict
    )

    if authenticated_available:
        authz_state["authenticated_session"] = (
            authenticated_session
        )
        authz_state["authenticated_available"] = True

        authz_state["privilege_boundary_context"] = True

        authz_state["chain_context"] = {
            "enabled": True,
            "type": "authenticated_to_authorization",
            "reason": (
                "An authenticated session was supplied to "
                "the Authorization specialist."
            ),
        }

    else:
        authz_state["authenticated_session"] = None
        authz_state["authenticated_available"] = False

        authz_state["privilege_boundary_context"] = False

        authz_state["chain_context"] = {
            "enabled": False,
            "type": None,
            "reason": (
                "No authenticated session was available."
            ),
        }

    print()
    print("=" * 70)
    print("AUTHORIZATION SPECIALIST AGENT")
    print("=" * 70)

    print()
    print("AUTHENTICATED SESSION")
    print("-" * 40)

    if authz_state.get("authenticated_available"):
        print("Available: True")
    else:
        print("Available: False")

    print()
    print("PRIVILEGE BOUNDARY CONTEXT")
    print("-" * 40)

    if authz_state.get("privilege_boundary_context"):
        print("Enabled: True")
        print(
            "Mode: Authenticated privilege-boundary analysis"
        )
    else:
        print("Enabled: False")
        print(
            "Mode: Unauthenticated authorization analysis"
        )

    print()
    print("CHAIN CONTEXT")
    print("-" * 40)

    chain_context = authz_state.get(
        "chain_context",
        {}
    )

    print({
        "enabled": chain_context.get(
            "enabled",
            False
        ),
        "type": chain_context.get(
            "type"
        ),
    })

    print()
    print("DISCOVERED AUTHORIZATION TARGETS")
    print("-" * 40)

    discovered = authz_state.get(
        "discovered_targets",
        []
    )

    for index, target in enumerate(discovered):
        print(
            index,
            target
        )

    if not discovered:
        print("No authorization targets discovered.")

        return {
            "specialist": True,
            "targets_discovered": 0,
            "targets_tested": 0,
            "targets_remaining": 0,
            "findings": [],
            "observations": [],
            "authenticated_available": (
                authenticated_available
            ),
            "privilege_boundary_context": (
                authenticated_available
            ),
            "chain_context": chain_context,
            "completed": True,
        }

    tests = 0

    batch_queue = []

    while (
        authz_state.get("remaining_targets")
        and tests < MAX_AUTHORIZATION_TESTS
    ):

        if not batch_queue:

            decision = choose_authorization_target(
                authz_state
            )

            if decision.get("action") == "finish":
                break

            batch_queue = decision.get(
                "targets",
                []
            )

            if not batch_queue:
                break

            reason = decision.get(
                "reason",
                "Authorization targets selected."
            )

            print()
            print("GPT-OSS AUTHORIZATION BATCH DECISION")
            print("-" * 40)

            print({
                "action": "test",
                "targets_selected": len(batch_queue),
                "reason": reason,
            })

        target = batch_queue.pop(0)

        if not target:
            continue

        print()
        print("AUTHORIZATION TARGET SELECTED")
        print("-" * 40)

        print(target)

        try:
            result = execute_authorization_test(
                authz_state,
                target
            )

            result = sanitize_authorization_result(
                result
            )

        except Exception as exc:
            result = {
                "success": False,
                "error": str(exc),
                "data": {
                    "vulnerable": False,
                    "detail": (
                        "Authorization test failed."
                    )
                },
            }

        print()
        print("AUTHORIZATION TEST RESULT")
        print("-" * 40)

        print(result)

        authz_state = update_authorization_state(
            authz_state,
            target,
            result,
            reason
        )

        tests += 1

    authz_state = finish_authorization_state(
        authz_state
    )

    print()
    print("=" * 70)
    print("AUTHORIZATION SPECIALIST COMPLETE")
    print("=" * 70)

    print(
        "Targets discovered:",
        len(
            authz_state.get(
                "discovered_targets",
                []
            )
        )
    )

    print(
        "Targets tested:",
        len(
            authz_state.get(
                "tested_targets",
                []
            )
        )
    )

    print(
        "Successful findings:",
        len(
            authz_state.get(
                "findings",
                []
            )
        )
    )

    print(
        "Remaining targets:",
        len(
            authz_state.get(
                "remaining_targets",
                []
            )
        )
    )

    print(
        "Privilege boundary context:",
        authz_state.get(
            "privilege_boundary_context",
            False
        )
    )

    authz_findings = authz_state.get("findings", [])

    return {
        "specialist": True,

        "vulnerable": len(authz_findings) > 0,

        "data": {
            "vulnerable": len(authz_findings) > 0,
            "findings": authz_findings,
            "successful_targets": authz_findings,
            "detail": (
                f"Authorization analysis completed across "
                f"{len(authz_state.get('tested_targets', []))} endpoints; "
                f"{len(authz_findings)} finding(s)."
            ),
        },

        "targets_discovered": len(
            authz_state.get(
                "discovered_targets",
                []
            )
        ),

        "targets_tested": len(
            authz_state.get(
                "tested_targets",
                []
            )
        ),

        "targets_remaining": len(
            authz_state.get(
                "remaining_targets",
                []
            )
        ),

        "findings": authz_state.get(
            "findings",
            []
        ),

        "observations": authz_state.get(
            "observations",
            []
        ),

        "authenticated_available": authz_state.get(
            "authenticated_available",
            False
        ),

        "privilege_boundary_context": authz_state.get(
            "privilege_boundary_context",
            False
        ),

        "chain_context": authz_state.get(
            "chain_context",
            {}
        ),

        "completed": authz_state.get(
            "completed",
            False
        ),

        "state": authz_state,
    }