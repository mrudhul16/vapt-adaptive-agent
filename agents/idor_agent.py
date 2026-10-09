import json
import re

from dotenv import load_dotenv
from groq_key_manager import get_llm


load_dotenv()


llm = get_llm("idor")


SYSTEM_PROMPT = """
You are an IDOR specialist AI agent working in an authorized
local web application security testing environment.

Your job is to decide which IDOR-related target should be
investigated next.

You must:

1. Examine discovered IDOR targets.
2. Check which targets were already tested.
3. Analyze previous observations.
4. Choose up to 5 unexplored targets.
5. Prefer targets involving user-specific resources,
   object IDs, baskets, orders, profiles, or similar
   authorization boundaries.
6. Explain briefly why the target should be tested.
7. If no unexplored relevant targets remain, finish.

Never invent a target.

Do not request, expose, or reproduce authentication tokens,
cookies, session secrets, or other credentials.

Return ONLY valid JSON.

Format:

{
    "action": "test" or "finish",
    "target_indices": [0, 1, 2, 3, 4],
    "reason": "short explanation"
}
"""


def choose_next_target(state):

    idor_state = state["idor_state"]

    discovered_targets = (
        idor_state["discovered_targets"]
    )

    tested_targets = (
        idor_state["tested_targets"]
    )

    observations = (
        idor_state["observations"]
    )

    remaining_targets = []

    for index, target in enumerate(
        discovered_targets
    ):

        if target not in tested_targets:

            remaining_targets.append({
                "index": index,
                "target": target
            })

    if not remaining_targets:
        return {
            "action": "finish",
            "targets": [],
            "reason": "No unexplored IDOR targets remain."
        }

    authenticated_session = (
        idor_state.get(
            "authenticated_session",
            {}
        )
    )

    session_available = bool(
        authenticated_session
    )

    BATCH_SIZE = 5

    # Compact: present only the untested targets, by their discovered index,
    # without duplicate lists, full observations, or indentation whitespace.
    remaining_compact = [
        {
            "i": rt["index"],
            "url": (
                rt["target"].get("url")
                if isinstance(rt["target"], dict) else str(rt["target"])
            ),
            "m": (
                rt["target"].get("method", "GET")
                if isinstance(rt["target"], dict) else "GET"
            ),
        }
        for rt in remaining_targets
    ]

    prompt = f"""IDOR specialist. Target: {state["target_url"]}
Authenticated session available: {session_available}
Pick up to {BATCH_SIZE} targets to test, by their "i" index, from this remaining list:
{json.dumps(remaining_compact, separators=(",", ":"))}
Only choose indices listed above. Do not invent targets. The session is used by the
tool internally; never ask for or output the token.
Return ONLY JSON: {{"action":"test","target_indices":[..],"reason":"short"}} or {{"action":"finish","target_indices":[],"reason":"short"}}"""

    try:
        response = llm.invoke(
            [
                (
                    "system",
                    SYSTEM_PROMPT
                ),
                (
                    "human",
                    prompt
                )
            ]
        )
        decision = parse_decision(
            response.content
        )
    except Exception as e:
        print(f"[IDOR] GPT decision failed: {e}")
        decision = None
        decision = None

    if decision is None:
        selected_targets = [
            t["target"] for t in remaining_targets[:BATCH_SIZE]
        ]
        return {
            "action": "test",
            "targets": selected_targets,
            "reason": "Fallback to first remaining IDOR targets.",
        }

    if decision.get("action") == "finish":
        return {
            "action": "finish",
            "targets": [],
            "reason": decision.get("reason", "No unexplored IDOR targets remain.")
        }

    selected_targets = []
    
    for index in decision.get("target_indices", [])[:BATCH_SIZE]:
        if not isinstance(index, int) or index < 0 or index >= len(discovered_targets):
            continue
            
        target = discovered_targets[index]
        selected_targets.append(target)

    if not selected_targets:
        selected_targets = [
            t["target"] for t in remaining_targets[:BATCH_SIZE]
        ]

    return {
        "action": "test",
        "targets": selected_targets,
        "reason": decision.get(
            "reason",
            "Selected by GPT-OSS."
        )
    }


def parse_decision(response_text):

    response_text = response_text.strip()


    try:

        return json.loads(
            response_text
        )


    except json.JSONDecodeError:

        match = re.search(
            r"\{.*\}",
            response_text,
            re.DOTALL
        )


        if not match:

            raise ValueError(
                "GPT-OSS returned an invalid decision."
            )


        return json.loads(
            match.group(0)
        )


def update_idor_state(
    state,
    target,
    result,
    reason
):

    idor_state = state["idor_state"]


    if target not in idor_state[
        "tested_targets"
    ]:

        idor_state[
            "tested_targets"
        ].append(target)


    observation = {
        "target": target,
        "result": result,
        "reason": reason
    }


    idor_state[
        "observations"
    ].append(
        observation
    )


    if result.get(
        "data",
        {}
    ).get("vulnerable"):

        if target not in idor_state[
            "successful_targets"
        ]:

            idor_state[
                "successful_targets"
            ].append(target)


    idor_state[
        "remaining_targets"
    ] = [
        item
        for item in idor_state[
            "discovered_targets"
        ]
        if item not in idor_state[
            "tested_targets"
        ]
    ]


    idor_state[
        "current_target"
    ] = None


    idor_state[
        "iteration"
    ] += 1


    return state