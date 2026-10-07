from agents.recon_agent import (
    choose_next_targets,
    update_recon_state,
)

from tools.recon_tools import (
    discover_recon_targets,
    execute_recon_test,
)


MAX_BATCHES = 10
MAX_TARGETS_PER_BATCH = 5


def classify_target(target):

    if not isinstance(target, dict):
        return "other"

    target_type = target.get(
        "type",
        ""
    )

    url = target.get(
        "url",
        ""
    ).lower()

    if (
        "/login" in url
        or "/logout" in url
        or "/register" in url
        or "/change-password" in url
        or "/reset-password" in url
        or "/whoami" in url
        or "/authentication" in url
        or "/security-question" in url
        or "/security-questions" in url
    ):
        return "authentication"

    if (
        "/admin" in url
        or "/users" in url
        or "/user/" in url
        or "/address" in url
        or "/profile" in url
        or "/account" in url
        or "/permission" in url
        or "/permissions" in url
        or "/role" in url
        or "/roles" in url
    ):
        return "authorization"

    if (
        "/basket" in url
        or "/order" in url
        or "/payment" in url
        or "/wallet" in url
        or "/delivery" in url
        or "/card" in url
        or "/quantity" in url
        or "/checkout" in url
    ):
        return "transactions"

    if (
        target_type == "input"
        or target_type == "form"
        or "search" in url
        or "query" in url
        or "feedback" in url
        or "contact" in url
        or "comment" in url
    ):
        return "injection"

    if (
        target_type == "js"
        or url.endswith(".js")
        or ".js?" in url
    ):
        return "client_side"

    if (
        "/api/" in url
        or "/rest/" in url
    ):
        return "user_data"

    if target_type in (
        "page",
        "html",
        "form",
        "input",
    ):
        return "other"

    if target_type == "endpoint":
        return "other"

    return "other"


def classify_attack_surface(
    recon_state
):

    attack_surface = {
        "authentication": [],
        "authorization": [],
        "user_data": [],
        "transactions": [],
        "injection": [],
        "client_side": [],
        "other": [],
    }

    seen = set()

    discovered_targets = recon_state.get(
        "discovered_targets",
        []
    )

    for target in discovered_targets:

        if not isinstance(
            target,
            dict
        ):
            continue

        url = target.get(
            "url"
        )

        if not url:
            continue

        if url in seen:
            continue

        seen.add(url)

        category = classify_target(
            target
        )

        attack_surface[
            category
        ].append(
            {
                "url": url,
                "type": target.get(
                    "type",
                    "unknown"
                ),
            }
        )

    endpoints = recon_state.get(
        "endpoints",
        []
    )

    for endpoint in endpoints:

        if not isinstance(
            endpoint,
            str
        ):
            continue

        if endpoint in seen:
            continue

        seen.add(endpoint)

        target = {
            "url": endpoint,
            "type": "endpoint",
        }

        category = classify_target(
            target
        )

        attack_surface[
            category
        ].append(
            {
                "url": endpoint,
                "type": "endpoint",
            }
        )

    recon_state[
        "attack_surface"
    ] = attack_surface

    recon_state[
        "api_endpoints"
    ] = []

    recon_state[
        "auth_endpoints"
    ] = []

    recon_state[
        "user_endpoints"
    ] = []

    recon_state[
        "transaction_endpoints"
    ] = []

    recon_state[
        "page_endpoints"
    ] = []

    recon_state[
        "js_assets"
    ] = []

    recon_state[
        "other_endpoints"
    ] = []

    all_targets = []

    for target in recon_state.get(
        "discovered_targets",
        []
    ):

        if not isinstance(
            target,
            dict
        ):
            continue

        url = target.get(
            "url"
        )

        if not url:
            continue

        all_targets.append(
            {
                "url": url,
                "type": target.get(
                    "type",
                    "unknown"
                ),
            }
        )

    for endpoint in recon_state.get(
        "endpoints",
        []
    ):

        if not isinstance(
            endpoint,
            str
        ):
            continue

        all_targets.append(
            {
                "url": endpoint,
                "type": "endpoint",
            }
        )

    seen_urls = set()

    for item in all_targets:

        url = item[
            "url"
        ]

        if url in seen_urls:
            continue

        seen_urls.add(
            url
        )

        lower_url = url.lower()

        target_type = item[
            "type"
        ]

        if (
            target_type == "js"
            or lower_url.endswith(".js")
            or ".js?" in lower_url
        ):

            recon_state[
                "js_assets"
            ].append(
                url
            )

        elif (
            "/login" in lower_url
            or "/register" in lower_url
            or "/logout" in lower_url
            or "/change-password" in lower_url
            or "/reset-password" in lower_url
            or "/whoami" in lower_url
            or "/authentication" in lower_url
            or "/security-question" in lower_url
            or "/security-questions" in lower_url
        ):

            recon_state[
                "auth_endpoints"
            ].append(
                url
            )

        elif (
            "/admin" in lower_url
            or "/users" in lower_url
            or "/user/" in lower_url
            or "/address" in lower_url
            or "/profile" in lower_url
            or "/account" in lower_url
            or "/permission" in lower_url
            or "/permissions" in lower_url
            or "/role" in lower_url
            or "/roles" in lower_url
        ):

            recon_state[
                "user_endpoints"
            ].append(
                url
            )

        elif (
            "/basket" in lower_url
            or "/order" in lower_url
            or "/payment" in lower_url
            or "/wallet" in lower_url
            or "/delivery" in lower_url
            or "/card" in lower_url
            or "/quantity" in lower_url
            or "/checkout" in lower_url
        ):

            recon_state[
                "transaction_endpoints"
            ].append(
                url
            )

        elif (
            "/api/" in lower_url
            or "/rest/" in lower_url
        ):

            recon_state[
                "api_endpoints"
            ].append(
                url
            )

        elif target_type in (
            "page",
            "html",
            "form",
            "input",
        ):

            recon_state[
                "page_endpoints"
            ].append(
                url
            )

        else:

            recon_state[
                "other_endpoints"
            ].append(
                url
            )

    return recon_state


def run_recon_specialist(
    state
):

    print()
    print("=" * 60)
    print("RECON SPECIALIST STARTED")
    print("=" * 60)

    recon_state = state[
        "recon_state"
    ]

    recon_state[
        "target_url"
    ] = state.get(
        "target_url",
        "http://localhost:3000"
    )

    if not recon_state.get(
        "discovered_targets"
    ):

        print()
        print(
            "[RECON] Discovering attack surface..."
        )

        initial_targets = (
            discover_recon_targets(
                state
            )
        )

        if not isinstance(
            initial_targets,
            list
        ):

            raise TypeError(
                "discover_recon_targets() "
                "must return a list."
            )

        normalized_targets = []

        seen = set()

        for target in initial_targets:

            if not isinstance(
                target,
                dict
            ):
                continue

            url = target.get(
                "url"
            )

            if not url:
                continue

            if url in seen:
                continue

            seen.add(
                url
            )

            normalized_targets.append(
                target
            )

        recon_state[
            "discovered_targets"
        ] = normalized_targets

        recon_state[
            "remaining_targets"
        ] = normalized_targets.copy()

        print(
            "[RECON] Initial targets discovered:",
            len(
                normalized_targets
            )
        )

    classify_attack_surface(
        recon_state
    )

    batches = 0

    while (
        recon_state.get(
            "remaining_targets"
        )
        and batches < MAX_BATCHES
    ):

        batches += 1

        print()
        print(
            f"[RECON] Batch "
            f"{batches}/{MAX_BATCHES}"
        )

        print(
            "[RECON] Remaining targets:",
            len(
                recon_state.get(
                    "remaining_targets",
                    []
                )
            )
        )

        # IMPORTANT:
        # Pass recon_state, NOT the complete AgentState.
        decision = choose_next_targets(
            recon_state
        )

        if not isinstance(
            decision,
            dict
        ):

            print(
                "[RECON] Invalid GPT decision."
            )

            break

        action = decision.get(
            "action"
        )

        reason = decision.get(
            "reason",
            ""
        )

        target_indices = decision.get(
            "target_indices",
            []
        )

        # If GPT tries to finish while targets
        # remain, use the highest-priority
        # remaining targets instead.
        if (
            action == "finish"
            and recon_state.get(
                "remaining_targets"
            )
        ):

            print(
                "[RECON] GPT attempted to finish "
                "while targets remain."
            )

            remaining = (
                recon_state[
                    "remaining_targets"
                ]
            )

            selected_targets = (
                remaining[
                    :MAX_TARGETS_PER_BATCH
                ]
            )

        else:

            selected_targets = []

            discovered_targets = (
                recon_state[
                    "discovered_targets"
                ]
            )

            tested_urls = set(
                recon_state.get(
                    "tested_targets",
                    []
                )
            )

            if not isinstance(
                target_indices,
                list
            ):

                target_indices = []

            for index in target_indices:

                try:
                    index = int(
                        index
                    )

                except (
                    TypeError,
                    ValueError
                ):
                    continue

                if (
                    index < 0
                    or index >= len(
                        discovered_targets
                    )
                ):
                    continue

                target = (
                    discovered_targets[
                        index
                    ]
                )

                if not isinstance(
                    target,
                    dict
                ):
                    continue

                url = target.get(
                    "url"
                )

                if not url:
                    continue

                if url in tested_urls:
                    continue

                selected_targets.append(
                    target
                )

            selected_targets = (
                selected_targets[
                    :MAX_TARGETS_PER_BATCH
                ]
            )

        if not selected_targets:

            print(
                "[RECON] No valid unexplored "
                "targets selected."
            )

            break

        for target in selected_targets:

            url = target.get(
                "url"
            )

            print()
            print(
                f"[RECON] Testing: {url}"
            )

            try:

                observation = (
                    execute_recon_test(
                        state,
                        target
                    )
                )

            except Exception as exc:

                observation = {
                    "success": False,
                    "data": {
                        "error": str(
                            exc
                        )
                    }
                }

            if url not in recon_state[
                "tested_targets"
            ]:

                recon_state[
                    "tested_targets"
                ].append(
                    url
                )

            recon_state[
                "remaining_targets"
            ] = [
                item
                for item in recon_state[
                    "remaining_targets"
                ]
                if (
                    isinstance(
                        item,
                        dict
                    )
                    and item.get(
                        "url"
                    ) != url
                )
            ]

            observation_record = {
                "target": target,
                "result": observation,
                "reason": reason,
            }

            recon_state[
                "observations"
            ].append(
                observation_record
            )

            # The fresh recon_agent expects:
            # update_recon_state(recon_state, observations)
            update_recon_state(
                recon_state,
                [
                    observation_record
                ]
            )

            classify_attack_surface(
                recon_state
            )

            print(
                "[RECON] Tested:",
                url
            )

            print(
                "[RECON] Remaining:",
                len(
                    recon_state.get(
                        "remaining_targets",
                        []
                    )
                )
            )

        if not recon_state.get(
            "remaining_targets"
        ):
            break

    classify_attack_surface(
        recon_state
    )

    recon_state[
        "completed"
    ] = not bool(
        recon_state.get(
            "remaining_targets"
        )
    )

    print()
    print("=" * 60)
    print("RECON SPECIALIST COMPLETE")
    print("=" * 60)

    print(
        "Targets discovered:",
        len(
            recon_state.get(
                "discovered_targets",
                []
            )
        )
    )

    print(
        "Targets tested:",
        len(
            recon_state.get(
                "tested_targets",
                []
            )
        )
    )

    print(
        "Targets remaining:",
        len(
            recon_state.get(
                "remaining_targets",
                []
            )
        )
    )

    print(
        "Endpoints discovered:",
        len(
            recon_state.get(
                "endpoints",
                []
            )
        )
    )

    print(
        "API endpoints:",
        len(
            recon_state.get(
                "api_endpoints",
                []
            )
        )
    )

    print(
        "Authentication endpoints:",
        len(
            recon_state.get(
                "auth_endpoints",
                []
            )
        )
    )

    print(
        "User endpoints:",
        len(
            recon_state.get(
                "user_endpoints",
                []
            )
        )
    )

    print(
        "Transaction endpoints:",
        len(
            recon_state.get(
                "transaction_endpoints",
                []
            )
        )
    )

    print(
        "Injection targets:",
        len(
            recon_state.get(
                "attack_surface",
                {}
            ).get(
                "injection",
                []
            )
        )
    )

    print(
        "Client-side targets:",
        len(
            recon_state.get(
                "attack_surface",
                {}
            ).get(
                "client_side",
                []
            )
        )
    )

    return {
        "finding_type": "recon",

        "data": {

            "targets_discovered": len(
                recon_state.get(
                    "discovered_targets",
                    []
                )
            ),

            "targets_tested": len(
                recon_state.get(
                    "tested_targets",
                    []
                )
            ),

            "targets_remaining": len(
                recon_state.get(
                    "remaining_targets",
                    []
                )
            ),

            "endpoints": recon_state.get(
                "endpoints",
                []
            ),

            "parameters": recon_state.get(
                "parameters",
                []
            ),

            "technologies": recon_state.get(
                "technologies",
                []
            ),

            "attack_surface": recon_state.get(
                "attack_surface",
                {}
            ),

            "api_endpoints": recon_state.get(
                "api_endpoints",
                []
            ),

            "auth_endpoints": recon_state.get(
                "auth_endpoints",
                []
            ),

            "user_endpoints": recon_state.get(
                "user_endpoints",
                []
            ),

            "transaction_endpoints": recon_state.get(
                "transaction_endpoints",
                []
            ),

            "js_assets": recon_state.get(
                "js_assets",
                []
            ),

        },

        "chain_trigger": False,
        "chain_data": None,
    }