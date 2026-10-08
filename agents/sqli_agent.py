import json
import re

from dotenv import load_dotenv
from groq_key_manager import get_llm

from tools.sqli_tools import (
    get_sqli_targets,
    execute_sqli_test
)


load_dotenv()


llm = get_llm("sqli")


SYSTEM_PROMPT = """
You are an SQL Injection specialist AI agent working in an
authorized local web application security testing environment.

Your job is to decide which SQL injection target should be
investigated next.

You must:

1. Examine discovered SQLi targets.
2. Check which targets were already tested.
3. Analyze previous observations.
4. Choose an unexplored target.
5. Prefer targets that are more likely to accept user-controlled
   database-related input.
6. Explain briefly why that target should be tested.
7. If there are no unexplored relevant targets, finish.

Never invent a target.

Return ONLY valid JSON.

Format:

{
    "action": "test" or "finish",
    "target_index": integer or null,
    "reason": "short explanation"
}
"""


def choose_next_target(state):

    sqli_state = state["sqli_state"]

    discovered_targets = sqli_state["discovered_targets"]
    tested_targets = sqli_state["tested_targets"]

    remaining_targets = []

    for index, target in enumerate(discovered_targets):

        if target not in tested_targets:

            remaining_targets.append({
                "index": index,
                "target": target
            })


    if not remaining_targets:

        return {
            "action": "finish",
            "target_index": None,
            "reason": "No unexplored SQLi targets remain."
        }


    prompt = f"""
Target:
{state["target_url"]}

Remaining SQLi targets:
{json.dumps(remaining_targets, indent=2)}

Previously tested targets:
{json.dumps(tested_targets, indent=2)}

Previous observations:
{json.dumps(
    sqli_state["observations"][-5:],
    indent=2
)}

Choose ONE target from the remaining targets.

Do not invent a target.

Return only JSON.
"""


    response = llm.invoke(
        [
            ("system", SYSTEM_PROMPT),
            ("human", prompt)
        ]
    )


    return parse_decision(
        response.content
    )


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


def sanitize_result(result):

    data = result.get(
        "data",
        {}
    )


    safe_data = {}

    for key, value in data.items():

        if key in {
            "storage",
            "authenticated_session",
            "token",
            "auth_token"
        }:

            continue


        if key == "chain_data":

            if isinstance(value, dict):

                safe_data[key] = {
                    "chain": value.get("chain"),
                    "reason": value.get("reason"),
                    "authenticated": value.get(
                        "authenticated",
                        False
                    ),
                    "auth_token_found": value.get(
                        "auth_token_found",
                        False
                    ),
                    "auth_token_source": value.get(
                        "auth_token_source"
                    )
                }

            continue


        safe_data[key] = value


    return {
        "success": result.get(
            "success",
            False
        ),
        "data": safe_data
    }


def update_sqli_state(
    state,
    target,
    result,
    reason
):

    sqli_state = state["sqli_state"]


    if target not in sqli_state["tested_targets"]:

        sqli_state["tested_targets"].append(
            target
        )


    safe_result = sanitize_result(
        result
    )


    observation = {
        "target": target,
        "result": safe_result,
        "reason": reason
    }


    sqli_state["observations"].append(
        observation
    )


    if result.get(
        "data",
        {}
    ).get(
        "vulnerable"
    ):

        if target not in sqli_state[
            "successful_targets"
        ]:

            sqli_state[
                "successful_targets"
            ].append(
                target
            )


    sqli_state["remaining_targets"] = [
        item
        for item in sqli_state[
            "discovered_targets"
        ]
        if item not in sqli_state[
            "tested_targets"
        ]
    ]


    sqli_state["current_target"] = None

    sqli_state["iteration"] += 1


    return state


def test_selected_target(
    state,
    target,
    reason
):

    print()
    print(
        "SQLI TARGET SELECTED"
    )
    print(
        "=" * 40
    )

    print(target)


    result = execute_sqli_test(
        state,
        target
    )


    safe_result = sanitize_result(
        result
    )


    print()
    print(
        "SQLI TEST RESULT"
    )
    print(
        "=" * 40
    )

    print(
        safe_result
    )


    update_sqli_state(
        state,
        target,
        result,
        reason
    )


    return result