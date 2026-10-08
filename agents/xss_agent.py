import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from dotenv import load_dotenv
from groq_key_manager import get_llm

from tools.xss_tools import execute_xss_test

load_dotenv()

llm = get_llm("xss")

MAX_XSS_TARGETS = 20
BATCH_SIZE = 5
MAX_LLM_CALLS = 4


SYSTEM_PROMPT = """
You are an XSS specialist AI agent working in an authorized
local web application security testing environment.

Your task is to select the most useful XSS targets from a
provided candidate list.

Prioritize:
1. Actual input fields
2. Form parameters
3. Query parameters
4. API parameters
5. Search functionality
6. User-controlled URL parameters
7. Other likely reflected/stored XSS entry points

Avoid:
- Static assets
- CSS
- Images
- Fonts
- JavaScript files unless they represent a useful input endpoint
- Duplicate URLs
- Targets already tested

You may select multiple targets.

Return ONLY valid JSON.

Format:
{
    "action": "test" or "finish",
    "target_indices": [0, 1, 2],
    "reason": "short explanation"
}
"""


def _target_url(target):
    if isinstance(target, str):
        return target

    if isinstance(target, dict):
        return str(
            target.get("url")
            or target.get("endpoint")
            or target.get("target")
            or ""
        )

    return ""


def _target_type(target):
    if isinstance(target, dict):
        return str(target.get("type") or "").lower()

    return ""


def _target_parameter(target):
    if not isinstance(target, dict):
        return ""

    return str(
        target.get("parameter")
        or target.get("name")
        or target.get("input_name")
        or ""
    ).strip().lower()


def _target_method(target):
    if isinstance(target, dict):
        return str(target.get("method") or "GET").upper()

    return "GET"


def _normalize_url(url):
    if not url:
        return ""

    try:
        parsed = urlsplit(url)

        path = parsed.path.rstrip("/") or "/"

        query_items = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        query_items.sort()

        query = urlencode(query_items)

        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                path,
                query,
                ""
            )
        )

    except Exception:
        return str(url).strip().rstrip("/")


def _target_identity(target):
    """
    Create a stable identity for XSS targets.

    Primary identity:
        normalized URL + meaningful parameter/input

    This prevents duplicates such as:
        /contact
        /contact

    appearing multiple times because their metadata differs.

    Different parameters on the same endpoint remain separate:
        /search?q=
        /search?name=
    """

    url = _normalize_url(_target_url(target))
    parameter = _target_parameter(target)
    method = _target_method(target)

    return (
        method,
        url,
        parameter
    )


def _is_static_target(target):
    url = _target_url(target).lower()

    static_extensions = (
        ".css",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp4",
        ".webm",
        ".pdf"
    )

    return any(
        part.split("?")[0].endswith(static_extensions)
        for part in [url]
    )


def _target_score(target):
    url = _target_url(target).lower()
    target_type = _target_type(target)
    parameter = _target_parameter(target)

    score = 0

    if _is_static_target(target):
        return -100

    if parameter:
        score += 10

    if target_type in {
        "input",
        "form",
        "parameter",
        "query",
        "api"
    }:
        score += 8

    interesting_words = (
        "search",
        "query",
        "contact",
        "comment",
        "feedback",
        "message",
        "profile",
        "user",
        "login",
        "register",
        "forgot",
        "password",
        "product",
        "review",
        "redirect",
        "return",
        "url"
    )

    for word in interesting_words:
        if word in url:
            score += 3

    if "?" in url:
        score += 5

    if "=" in url:
        score += 5

    if target_type in {"page", "endpoint"}:
        score += 2

    return score


def _deduplicate_targets(targets):
    """
    Remove duplicate XSS targets.

    Same normalized URL + same parameter = duplicate,
    regardless of differences in unrelated metadata.
    """

    unique = []
    seen = set()

    for target in targets:
        identity = _target_identity(target)

        if not identity[1]:
            continue

        if identity in seen:
            continue

        seen.add(identity)
        unique.append(target)

    return unique


def _prepare_candidate_targets(state):
    xss_state = state["xss_state"]

    discovered_targets = xss_state.get(
        "discovered_targets",
        []
    )

    tested_targets = xss_state.get(
        "tested_targets",
        []
    )

    tested_keys = {
        _target_identity(target)
        for target in tested_targets
    }

    candidates = []

    for target in discovered_targets:

        if not _target_url(target):
            continue

        if _is_static_target(target):
            continue

        identity = _target_identity(target)

        if identity in tested_keys:
            continue

        candidates.append(target)

    candidates = _deduplicate_targets(candidates)

    candidates.sort(
        key=_target_score,
        reverse=True
    )

    return candidates[:MAX_XSS_TARGETS]


def choose_next_target(state):
    """
    GPT selects a batch of useful targets.

    The runner still tests one target at a time.
    We maintain a local queue so GPT does not need
    to make a new decision for every target.
    """

    xss_state = state["xss_state"]

    batch_queue = xss_state.setdefault(
        "_batch_queue",
        []
    )

    if batch_queue:
        target = batch_queue.pop(0)

        return {
            "action": "test",
            "target_index": xss_state[
                "discovered_targets"
            ].index(target),
            "reason": "Selected from the current GPT-prioritized XSS batch."
        }

    llm_calls = xss_state.get(
        "_llm_calls",
        0
    )

    if llm_calls >= MAX_LLM_CALLS:
        return {
            "action": "finish",
            "target_index": None,
            "reason": "Maximum XSS LLM decision budget reached."
        }

    candidates = _prepare_candidate_targets(state)

    if not candidates:
        return {
            "action": "finish",
            "target_index": None,
            "reason": "No unexplored XSS targets remain."
        }

    compact_candidates = []

    for index, target in enumerate(candidates):

        compact_candidates.append(
            {
                "index": index,
                "url": _target_url(target),
                "type": _target_type(target),
                "parameter": _target_parameter(target),
                "method": _target_method(target)
            }
        )

    observations = xss_state.get(
        "observations",
        []
    )

    compact_observations = observations[-5:]

    prompt = f"""
Target:
{state["target_url"]}

Candidate XSS targets:
{json.dumps(compact_candidates, indent=2)}

Recently observed results:
{json.dumps(compact_observations, indent=2)}

Select up to {BATCH_SIZE} of the most promising targets.

Return:
{{
    "action": "test",
    "target_indices": [0, 1, 2],
    "reason": "short explanation"
}}

If no useful targets remain:
{{
    "action": "finish",
    "target_indices": [],
    "reason": "short explanation"
}}
"""

    xss_state["_llm_calls"] = llm_calls + 1

    try:
        response = llm.invoke(
            [
                ("system", SYSTEM_PROMPT),
                ("human", prompt)
            ]
        )

        decision = parse_decision(
            response.content
        )

    except Exception as e:
        print(
            f"[XSS] GPT decision failed: {e}"
        )

        fallback = candidates[:BATCH_SIZE]

        if not fallback:
            return {
                "action": "finish",
                "target_index": None,
                "reason": "No XSS targets available."
            }

        xss_state["_batch_queue"] = fallback[1:]

        return {
            "action": "test",
            "target_index": xss_state[
                "discovered_targets"
            ].index(fallback[0]),
            "reason": "Local fallback target selection."
        }

    if decision.get("action") == "finish":
        return {
            "action": "finish",
            "target_index": None,
            "reason": decision.get(
                "reason",
                "GPT decided to finish XSS testing."
            )
        }

    indices = decision.get(
        "target_indices",
        []
    )

    if not isinstance(indices, list):
        indices = []

    selected = []

    for index in indices[:BATCH_SIZE]:

        if not isinstance(index, int):
            continue

        if index < 0 or index >= len(candidates):
            continue

        target = candidates[index]

        if target not in selected:
            selected.append(target)

    if not selected:
        selected = candidates[:BATCH_SIZE]

    first_target = selected[0]

    xss_state["_batch_queue"] = selected[1:]

    discovered_targets = xss_state[
        "discovered_targets"
    ]

    try:
        target_index = discovered_targets.index(
            first_target
        )
    except ValueError:
        return {
            "action": "finish",
            "target_index": None,
            "reason": "Selected XSS target was not found in discovered targets."
        }

    return {
        "action": "test",
        "target_index": target_index,
        "reason": decision.get(
            "reason",
            "Selected by GPT-OSS."
        )
    }


def parse_decision(response_text):
    response_text = response_text.strip()

    try:
        return json.loads(response_text)

    except json.JSONDecodeError:

        match = re.search(
            r"\{.*\}",
            response_text,
            re.DOTALL
        )

        if not match:
            raise ValueError(
                "Could not parse GPT XSS decision."
            )

        return json.loads(
            match.group(0)
        )


def update_xss_state(
    state,
    target,
    result,
    reason
):
    xss_state = state["xss_state"]

    if target not in xss_state["tested_targets"]:
        xss_state["tested_targets"].append(
            target
        )

    if target in xss_state["remaining_targets"]:
        xss_state["remaining_targets"].remove(
            target
        )

    data = result.get(
        "data",
        {}
    )

    observation = {
        "target": target,
        "reason": reason,
        "vulnerable": data.get(
            "vulnerable",
            False
        ),
        "detail": data.get(
            "detail",
            ""
        )
    }

    xss_state["observations"].append(
        observation
    )

    if data.get("vulnerable") is True:
        if target not in xss_state[
            "successful_targets"
        ]:
            xss_state[
                "successful_targets"
            ].append(target)


def test_selected_target(
    state,
    target,
    reason
):
    print(
        f"[XSS] Testing target: {target}"
    )

    result = execute_xss_test(
        state,
        target
    )

    update_xss_state(
        state,
        target,
        result,
        reason
    )

    return result