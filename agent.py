import json
import re

from dotenv import load_dotenv
from langchain_groq import ChatGroq

from state import initial_state

from agents.recon_runner import run_recon_specialist
from agents.auth_runner import run_auth_specialist
from agents.sqli_runner import run_sqli_specialist
from agents.idor_runner import run_idor_specialist
from agents.authorization_runner import run_authorization_specialist

from agents.xss_agent import (
    choose_next_target,
    test_selected_target,
)

from modules.risk_engine import analyze_all


load_dotenv()


llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0
)


CORE_MODULES = [
    "recon",
    "auth",
    "sqli_check",
    "xss_check",
    "authorization",
]


def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(
            str(text)
            .encode("ascii", errors="replace")
            .decode("ascii")
        )


def get_target_url(state):
    return state.get(
        "target_url",
        "http://localhost:3000"
    )


def get_authenticated_session(state):
    session = state.get(
        "authenticated_session"
    )

    if session:
        return session

    sqli_state = state.get(
        "sqli_state",
        {}
    )

    session = sqli_state.get(
        "authenticated_session"
    )

    if session:
        return session

    auth_state = state.get(
        "auth_state",
        {}
    )

    session = auth_state.get(
        "authenticated_session"
    )

    if session:
        return session

    idor_state = state.get(
        "idor_state",
        {}
    )

    session = idor_state.get(
        "authenticated_session"
    )

    if session:
        return session

    return None


def sanitize_session_from_result(result):
    if not isinstance(result, dict):
        return result

    cleaned = dict(result)

    sensitive_keys = [
        "authenticated_session",
        "auth_session",
        "session",
        "token",
        "access_token",
        "jwt",
        "authorization",
        "cookie",
    ]

    for key in sensitive_keys:
        cleaned.pop(key, None)

    data = cleaned.get("data")

    if isinstance(data, dict):
        data = dict(data)

        for key in sensitive_keys:
            data.pop(key, None)

        cleaned["data"] = data

    return cleaned


def extract_recon_result(state):
    recon_state = state.get(
        "recon_state",
        {}
    )

    if isinstance(
        recon_state,
        dict
    ):
        return {
            "finding_type": "recon",
            "category": "recon",
            "vulnerable": False,
            "data": recon_state,
        }

    findings = state.get(
        "findings",
        []
    )

    recon_findings = []

    for finding in findings:
        if not isinstance(
            finding,
            dict
        ):
            continue

        finding_type = (
            finding.get("finding_type")
            or finding.get("category")
        )

        if finding_type == "recon":
            recon_findings.append(
                finding
            )

    if recon_findings:
        return recon_findings[-1]

    return {}


def initialize_xss_state(
    state,
    recon_result
):
    existing = state.get(
        "xss_state"
    )

    if isinstance(existing, dict) and existing.get(
        "discovered_targets"
    ):
        return state

    recon_data = {}

    if isinstance(
        recon_result,
        dict
    ):
        recon_data = recon_result.get(
            "data",
            {}
        )

    if not isinstance(
        recon_data,
        dict
    ):
        recon_data = {}

    attack_surface = recon_data.get(
        "attack_surface",
        {}
    )

    if not isinstance(
        attack_surface,
        dict
    ):
        attack_surface = {}

    discovered_targets = []

    categories = [
        "injection",
        "client_side",
        "page_endpoints",
        "api_endpoints",
        "user_endpoints",
        "transaction_endpoints",
        "js_assets",
    ]

    for category in categories:

        targets = attack_surface.get(
            category,
            []
        )

        if not isinstance(
            targets,
            list
        ):
            continue

        for target in targets:

            if isinstance(
                target,
                dict
            ):
                if (
                    target.get("url")
                    or target.get("target")
                    or target.get("endpoint")
                ):
                    discovered_targets.append(
                        dict(target)
                    )

            elif isinstance(
                target,
                str
            ):
                discovered_targets.append(
                    {
                        "url": target
                    }
                )

    endpoints = recon_data.get(
        "endpoints",
        []
    )

    if isinstance(
        endpoints,
        list
    ):
        for endpoint in endpoints:

            if isinstance(
                endpoint,
                dict
            ):
                if (
                    endpoint.get("url")
                    or endpoint.get("endpoint")
                ):
                    discovered_targets.append(
                        dict(endpoint)
                    )

            elif isinstance(
                endpoint,
                str
            ):
                discovered_targets.append(
                    {
                        "url": endpoint
                    }
                )

    unique_targets = []
    seen_urls = set()

    for target in discovered_targets:

        url = str(
            target.get("url", "")
        ).strip()

        if not url:
            continue

        if url in seen_urls:
            continue

        seen_urls.add(url)

        unique_targets.append(
            target
        )

    state["xss_state"] = {
        "discovered_targets": unique_targets,
        "tested_targets": [],
        "successful_targets": [],
        "remaining_targets": list(
            unique_targets
        ),
        "observations": [],
        "current_target": None,
        "iteration": 0,
        "completed": False,
    }

    return state

def run_xss_specialist(
    state,
    recon_result
):
    initialize_xss_state(
        state,
        recon_result
    )

    xss_state = state[
        "xss_state"
    ]

    print("\n" + "=" * 70)
    print("XSS SPECIALIST")
    print("=" * 70)

    print(
        "Discovered XSS targets:",
        len(
            xss_state[
                "discovered_targets"
            ]
        )
    )

    while xss_state[
        "remaining_targets"
    ]:

        decision = choose_next_target(
            state
        )

        action = decision.get(
            "action"
        )

        target_index = decision.get(
            "target_index"
        )

        reason = decision.get(
            "reason",
            ""
        )

        if action == "finish":
            break

        if target_index is None:
            break

        try:
            target_index = int(
                target_index
            )

        except (
            TypeError,
            ValueError
        ):
            break

        discovered = xss_state[
            "discovered_targets"
        ]

        if (
            target_index < 0
            or target_index >= len(
                discovered
            )
        ):
            break

        target = discovered[
            target_index
        ]

        if target in xss_state[
            "tested_targets"
        ]:
            continue

        xss_state[
            "current_target"
        ] = target

        test_selected_target(
            state,
            target,
            reason
        )

    xss_state[
        "completed"
    ] = (
        len(
            xss_state[
                "remaining_targets"
            ]
        ) == 0
    )

    return {
        "specialist": "xss",
        "target_count": len(
            xss_state[
                "discovered_targets"
            ]
        ),
        "tested_count": len(
            xss_state[
                "tested_targets"
            ]
        ),
        "successful_count": len(
            xss_state[
                "successful_targets"
            ]
        ),
        "remaining_count": len(
            xss_state[
                "remaining_targets"
            ]
        ),
        "findings": list(
            xss_state[
                "successful_targets"
            ]
        ),
        "observations": list(
            xss_state[
                "observations"
            ]
        ),
        "completed": xss_state[
            "completed"
        ],
    }

def build_decision_prompt(state):

    executed = state.get(
        "modules_run",
        []
    )

    pending_chain = state.get(
        "pending_chain"
    )

    available_modules = [
        module
        for module in CORE_MODULES
        if module not in executed
    ]

    if isinstance(
        pending_chain,
        dict
    ):
        next_module = pending_chain.get(
            "next_module"
        )

        if (
            next_module
            and next_module not in available_modules
        ):
            available_modules.append(
                next_module
            )

    if not available_modules:
        return """
Return ONLY valid JSON:

{
    "action": "stop",
    "reason": "All available specialist modules have been executed."
}
"""

    recon = state.get(
        "recon_state",
        {}
    )

    sqli = state.get(
        "sqli_state",
        {}
    )

    xss = state.get(
        "xss_state",
        {}
    )

    idor = state.get(
        "idor_state",
        {}
    )

    recon_info = {
        "completed": bool(
            recon.get("completed")
        ),
        "targets_discovered": len(
            recon.get(
                "discovered_targets",
                []
            )
        ),
        "targets_tested": len(
            recon.get(
                "tested_targets",
                []
            )
        ),
        "auth_endpoints": len(
            recon.get(
                "auth_endpoints",
                []
            )
        ),
        "user_endpoints": len(
            recon.get(
                "user_endpoints",
                []
            )
        ),
        "injection_targets": len(
            recon.get(
                "attack_surface",
                {}
            ).get(
                "injection",
                []
            )
        ),
        "client_side_targets": len(
            recon.get(
                "attack_surface",
                {}
            ).get(
                "client_side",
                []
            )
        ),
        "authorization_targets": len(
            recon.get(
                "attack_surface",
                {}
            ).get(
                "authorization",
                []
            )
        ),
    }

    summary = {
        "target": state.get(
            "target_url",
            ""
        ),
        "executed_modules": executed,
        "available_modules": available_modules,
        "findings_count": len(
            state.get(
                "findings",
                []
            )
        ),
        "recon": recon_info,
        "sqli": {
            "completed": bool(
                sqli.get("completed")
            ),
            "successful_targets": len(
                sqli.get(
                    "successful_targets",
                    []
                )
            ),
        },
        "xss": {
            "completed": bool(
                xss.get("completed")
            ),
            "successful_targets": len(
                xss.get(
                    "successful_targets",
                    []
                )
            ),
        },
        "idor": {
            "completed": bool(
                idor.get("completed")
            ),
            "successful_targets": len(
                idor.get(
                    "successful_targets",
                    []
                )
            ),
        },
        "authenticated_session_available": bool(
            state.get(
                "authenticated_session"
            )
            or sqli.get(
                "authenticated_session"
            )
            or idor.get(
                "authenticated_session"
            )
        ),
        "pending_chain": {
            "exists": isinstance(
                pending_chain,
                dict
            ),
            "type": (
                pending_chain.get("type")
                if isinstance(
                    pending_chain,
                    dict
                )
                else None
            ),
            "source": (
                pending_chain.get("source")
                if isinstance(
                    pending_chain,
                    dict
                )
                else None
            ),
            "next_module": (
                pending_chain.get(
                    "next_module"
                )
                if isinstance(
                    pending_chain,
                    dict
                )
                else None
            ),
            "reason": (
                pending_chain.get(
                    "reason"
                )
                if isinstance(
                    pending_chain,
                    dict
                )
                else None
            ),
        },
    }

    return f"""
You are the central orchestrator for an
authorized local web application security
assessment.

Choose the next useful specialist module
based on the current state.

Never invent targets.
Never invent vulnerabilities.
Never expose authentication tokens.

Current compact state:

{json.dumps(
    summary,
    separators=(",", ":"),
    default=str
)}

Rules:

1. Recon before vulnerability testing.
2. Authentication after recon when authentication
   endpoints exist.
3. SQLi after recon when injection targets exist.
4. XSS when client-side or injection targets exist.
5. Authorization when authorization/user targets exist.
6. Do not repeat completed modules.
7. Prefer a module with meaningful untested targets.
8. If a pending adaptive chain exists, strongly
   consider its next_module because the state
   indicates why it was created.
9. Choose based on the complete compact state.
   Do not blindly follow or ignore the chain.
10. Never select idor_check unless it is present
    in available_modules.
11. Stop only when all useful available modules
    are completed.

Available actions:

recon
auth
sqli_check
xss_check
authorization
idor_check
stop

Return ONLY valid JSON:

{{
    "action": "module_name",
    "reason": "short explanation"
}}
"""


def parse_decision(response):

    text = response.content.strip()

    try:
        return json.loads(
            text
        )

    except json.JSONDecodeError:

        match = re.search(
            r"\{.*\}",
            text,
            re.DOTALL
        )

        if not match:
            raise ValueError(
                "GPT-OSS returned an invalid "
                "orchestrator decision."
            )

        return json.loads(
            match.group(0)
        )


def decide_next_module(state):

    prompt = build_decision_prompt(
        state
    )

    response = llm.invoke(
        [
            (
                "system",
                """
You are the central orchestration AI
for an authorized local web application
security testing system.

You coordinate specialist security agents.

Never invent targets.
Never invent vulnerabilities.
Never expose authentication tokens.

Return ONLY valid JSON.
"""
            ),
            (
                "human",
                prompt
            )
        ]
    )

    decision = parse_decision(
        response
    )

    action = decision.get(
        "action"
    )

    if action == "stop":
        return decision

    if action == "idor_check":
        return decision

    if action not in CORE_MODULES:

        return {
            "action": "stop",
            "reason": (
                "Invalid module selected "
                "by the orchestrator."
            )
        }

    return decision


def execute_module(
    state,
    decision
):

    action = decision.get(
        "action"
    )

    reason = decision.get(
        "reason",
        ""
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "ORCHESTRATOR DECISION"
    )

    print(
        "=" * 70
    )

    print(
        f"Action: {action}"
    )

    safe_print(
        f"Reason: {reason}"
    )

    if action == "recon":

        return run_recon_specialist(
            state
        )

    if action == "auth":

        recon_result = extract_recon_result(
            state
        )

        result = run_auth_specialist(
            recon_result
        )

        return sanitize_session_from_result(
            result
        )

    if action == "sqli_check":

        result = run_sqli_specialist(
            state
        )

        return sanitize_session_from_result(
            result
        )

    if action == "idor_check":

        pending_chain = state.get(
            "pending_chain"
        )

        authenticated_session = None

        if pending_chain:

            authenticated_session = (
                pending_chain.get(
                    "authenticated_session"
                )
            )

        if not authenticated_session:

            authenticated_session = (
                get_authenticated_session(
                    state
                )
            )

        if authenticated_session:

            state[
                "idor_state"
            ][
                "authenticated_session"
            ] = authenticated_session

        result = run_idor_specialist(
            state
        )

        state[
            "idor_state"
        ].pop(
            "authenticated_session",
            None
        )

        return sanitize_session_from_result(
            result
        )

    if action == "xss_check":

        recon_result = extract_recon_result(
            state
        )

        result = run_xss_specialist(
            state,
            recon_result
        )

        return sanitize_session_from_result(
            result
        )

    if action == "authorization":

        recon_result = extract_recon_result(
            state
        )

        authenticated_session = (
            get_authenticated_session(
                state
            )
        )

        result = run_authorization_specialist(
            recon_result,
            authenticated_session=(
                authenticated_session
            )
        )

        return sanitize_session_from_result(
            result
        )

    return {
        "specialist": action,
        "completed": False,
        "error": "Unknown module."
    }


def update_state_after_module(
    state,
    action,
    result,
    reason
):

    result = sanitize_session_from_result(
        result
    )

    finding = {
        "finding_type": action,
        "category": action,
        "vulnerable": False,
        "data": result,
    }

    if result.get(
        "vulnerable"
    ) is True:

        finding[
            "vulnerable"
        ] = True

    data = result.get(
        "data"
    )

    if isinstance(
        data,
        dict
    ):

        if data.get(
            "vulnerable"
        ) is True:

            finding[
                "vulnerable"
            ] = True

        if isinstance(
            data.get(
                "findings"
            ),
            list
        ):

            finding[
                "findings"
            ] = data[
                "findings"
            ]

    state[
        "findings"
    ].append(
        finding
    )

    if action not in state[
        "modules_run"
    ]:

        state[
            "modules_run"
        ].append(
            action
        )

    state[
        "step_count"
    ] += 1

    state[
        "metrics"
    ][
        "modules_executed"
    ] = len(
        state[
            "modules_run"
        ]
    )

    state[
        "metrics"
    ][
        "findings_discovered"
    ] = len(
        state[
            "findings"
        ]
    )

    state[
        "metrics"
    ][
        "workflow_steps"
    ] = state[
        "step_count"
    ]

    state[
        "decision_history"
    ].append(
        {
            "step": state[
                "step_count"
            ],
            "action": action,
            "reason": reason,
        }
    )

    state[
        "decision_log"
    ].append(
        f"Step {state['step_count']}: "
        f"{action} - {reason}"
    )


def handle_sqli_chain(
    state,
    result
):

    if not isinstance(
        result,
        dict
    ):
        return

    data = result.get(
        "data",
        {}
    )

    if not isinstance(
        data,
        dict
    ):
        data = {}

    chain_data = (
        data.get(
            "chain_data"
        )
        or result.get(
            "chain_data"
        )
    )

    if not isinstance(
        chain_data,
        dict
    ):
        return

    authenticated_session = (
        chain_data.get(
            "authenticated_session"
        )
    )

    if not authenticated_session:
        return

    if not state.get(
        "chaining_enabled",
        True
    ):
        return

    state[
        "pending_chain"
    ] = {
        "type": "sqli_to_idor",
        "source": "sqli_check",
        "next_module": "idor_check",
        "reason": (
            "SQL injection testing produced "
            "an authenticated session."
        ),
        "authenticated_session":
            authenticated_session,
    }

    state[
        "metrics"
    ][
        "chains_triggered"
    ] += 1

    state[
        "pending_chains"
    ].append(
        {
            "type": "sqli_to_idor",
            "source": "sqli_check",
            "next_module": "idor_check",
        }
    )


def complete_idor_chain(
    state
):

    pending_chain = state.get(
        "pending_chain"
    )

    if not pending_chain:
        return

    if pending_chain.get(
        "next_module"
    ) != "idor_check":
        return

    chain_record = {
        "type": pending_chain.get(
            "type"
        ),
        "source": pending_chain.get(
            "source"
        ),
        "next_module": "idor_check",
        "status": "completed",
    }

    state[
        "chain_history"
    ].append(
        chain_record
    )

    state[
        "metrics"
    ][
        "chains_completed"
    ] += 1

    state[
        "pending_chain"
    ] = None


def run_agent(
    target_url="http://localhost:3000"
):

    state = initial_state(
        target_url=target_url,
        chaining_enabled=True
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "VAPT ADAPTIVE AGENT"
    )

    print(
        "=" * 70
    )

    print(
        f"Target: {target_url}"
    )

    while not state.get(
        "done",
        False
    ):

        decision = decide_next_module(
            state
        )

        action = decision.get(
            "action"
        )

        reason = decision.get(
            "reason",
            ""
        )

        if action == "stop":

            state[
                "step_count"
            ] += 1

            state[
                "decision_history"
            ].append(
                {
                    "step": state[
                        "step_count"
                    ],
                    "action": "stop",
                    "reason": reason,
                }
            )

            state[
                "decision_log"
            ].append(
                f"Step {state['step_count']}: "
                f"stop - {reason}"
            )

            state[
                "metrics"
            ][
                "workflow_steps"
            ] = state[
                "step_count"
            ]

            state[
                "done"
            ] = True

            print(
                "\n" + "=" * 70
            )

            print(
                "ORCHESTRATOR STOPPED"
            )

            print(
                "=" * 70
            )

            safe_print(
                reason
            )

            break

        result = execute_module(
            state,
            decision
        )

        if action == "sqli_check":

            handle_sqli_chain(
                state,
                result
            )

        update_state_after_module(
            state,
            action,
            result,
            reason
        )

        if action == "idor_check":

            complete_idor_chain(
                state
            )

    state[
        "risk_assessments"
    ] = analyze_all(
        state[
            "findings"
        ]
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "FINAL RESULTS"
    )

    print(
        "=" * 70
    )

    print(
        "Modules Executed:",
        state[
            "metrics"
        ][
            "modules_executed"
        ]
    )

    print(
        "Findings Discovered:",
        state[
            "metrics"
        ][
            "findings_discovered"
        ]
    )

    print(
        "Chains Triggered:",
        state[
            "metrics"
        ][
            "chains_triggered"
        ]
    )

    print(
        "Chains Completed:",
        state[
            "metrics"
        ][
            "chains_completed"
        ]
    )

    print(
        "Workflow Steps:",
        state[
            "metrics"
        ][
            "workflow_steps"
        ]
    )

    print(
        "\nRisk Assessments:",
        len(
            state[
                "risk_assessments"
            ]
        )
    )

    for risk in state[
        "risk_assessments"
    ]:

        print(
            f"- {risk['category']}: "
            f"{risk['impact']}"
        )

    print(
        "\nDecision History:"
    )

    for decision in state[
        "decision_history"
    ]:

        safe_print(
            f"Step {decision['step']}: "
            f"{decision['action']} - "
            f"{decision['reason']}"
        )

    return state


if __name__ == "__main__":
    run_agent()