import json
import re

from dotenv import load_dotenv
from langchain_groq import ChatGroq


load_dotenv()


llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0
)


SYSTEM_PROMPT = """
You are an IDOR specialist AI agent working in an authorized
local web application security testing environment.

Your job is to decide which IDOR-related target should be
investigated next.

You must:

1. Examine discovered IDOR targets.
2. Check which targets were already tested.
3. Analyze previous observations.
4. Choose an unexplored target.
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
    "target_index": integer or null,
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
            "target_index": None,
            "reason": (
                "No unexplored IDOR targets remain."
            )
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


    prompt = f"""
Target:
{state["target_url"]}

Authenticated session available:
{session_available}

Discovered IDOR targets:
{json.dumps(
    discovered_targets,
    indent=2
)}

Already tested:
{json.dumps(
    tested_targets,
    indent=2
)}

Remaining targets:
{json.dumps(
    remaining_targets,
    indent=2
)}

Previous observations:
{json.dumps(
    observations,
    indent=2
)}

Choose the next IDOR target.

Only select a target from the remaining targets.

Do not invent a target.

The authenticated session is available to the testing
tool internally. Do not ask for or output the token.

Return only JSON.
"""


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