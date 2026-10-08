import json
import re

from dotenv import load_dotenv
from groq_key_manager import get_llm


load_dotenv()


llm = get_llm("recon")


SYSTEM_PROMPT = """
You are an autonomous Reconnaissance Security Specialist
working in an authorized local web application security
testing environment.

Your job is to select useful reconnaissance targets from
the supplied target list.

IMPORTANT RULES:

1. ONLY select targets from the supplied list.
2. NEVER invent a target.
3. NEVER select an already tested target.
4. You are NOT allowed to finish while meaningful unexplored
   targets remain.
5. Select up to 5 targets at a time.
6. Prefer application functionality over static resources.

HIGH PRIORITY:

- authentication endpoints
- login/register/logout
- password functionality
- admin endpoints
- authorization endpoints
- user/profile/account endpoints
- API endpoints
- REST endpoints
- basket/order/payment/transaction endpoints
- endpoints containing parameters
- search/input/form/contact/feedback functionality
- useful JavaScript assets

LOW PRIORITY:

- CSS
- images
- fonts
- favicon
- robots.txt
- polyfills
- obvious static assets

JavaScript files can still be useful for discovering
routes, API endpoints and client-side functionality.

Return ONLY valid JSON.

For testing:

{
    "action": "test",
    "target_indices": [0, 1, 2],
    "reason": "short explanation"
}

Only return finish when there are genuinely no meaningful
unexplored targets:

{
    "action": "finish",
    "target_indices": [],
    "reason": "No meaningful unexplored targets remain."
}
"""


MAX_LLM_CANDIDATES = 20
MAX_TARGETS_PER_DECISION = 5


def safe_print(value):
    try:
        print(value)
    except UnicodeEncodeError:
        text = str(value)
        print(
            text.encode(
                "ascii",
                errors="replace"
            ).decode("ascii")
        )


def normalize_target(target):
    if isinstance(target, str):
        return target.strip()

    if isinstance(target, dict):
        return (
            target.get("url")
            or target.get("target")
            or target.get("endpoint")
            or ""
        ).strip()

    return ""


def normalize_tested_target(target):
    return normalize_target(target)


def classify_target(target):
    value = normalize_target(target).lower()

    if not value:
        return "other"

    if any(
        keyword in value
        for keyword in [
            "/login",
            "/logout",
            "/register",
            "/signup",
            "/forgot",
            "/reset",
            "/password",
            "/whoami",
            "/authentication",
            "/security-question",
            "/security-questions",
        ]
    ):
        return "authentication"

    if any(
        keyword in value
        for keyword in [
            "/admin",
            "/permission",
            "/permissions",
            "/role",
            "/roles",
            "/users",
            "/user/",
            "/profile",
            "/account",
            "/address",
        ]
    ):
        return "authorization"

    if any(
        keyword in value
        for keyword in [
            "/basket",
            "/order",
            "/payment",
            "/wallet",
            "/delivery",
            "/card",
            "/checkout",
            "/quantity",
        ]
    ):
        return "transaction"

    if (
        "/api/" in value
        or "/rest/" in value
    ):
        return "api"

    if (
        "?" in value
        or "input" in value
        or "form" in value
        or "search" in value
        or "query" in value
        or "feedback" in value
        or "contact" in value
        or "comment" in value
    ):
        return "injection"

    if (
        value.endswith(".js")
        or ".js?" in value
        or "/js/" in value
        or "/assets/" in value
    ):
        return "client_side"

    return "other"


def target_priority(target):
    value = normalize_target(target).lower()
    category = classify_target(value)

    scores = {
        "authentication": 1000,
        "authorization": 950,
        "transaction": 900,
        "api": 850,
        "injection": 800,
        "client_side": 500,
        "other": 100,
    }

    score = scores.get(category, 100)

    auth_words = [
        "login",
        "logout",
        "register",
        "signup",
        "password",
        "session",
        "whoami",
        "security-question",
    ]

    authz_words = [
        "admin",
        "permission",
        "role",
        "users",
        "user/",
        "profile",
        "account",
        "address",
    ]

    transaction_words = [
        "basket",
        "order",
        "payment",
        "checkout",
        "wallet",
        "delivery",
        "card",
    ]

    injection_words = [
        "input",
        "form",
        "search",
        "query",
        "feedback",
        "contact",
        "comment",
    ]

    if any(
        word in value
        for word in auth_words
    ):
        score += 100

    if any(
        word in value
        for word in authz_words
    ):
        score += 90

    if any(
        word in value
        for word in transaction_words
    ):
        score += 80

    if any(
        word in value
        for word in injection_words
    ):
        score += 100

    if "?" in value:
        score += 150

    if "/api/" in value:
        score += 80

    if "/rest/" in value:
        score += 80

    if value.endswith(".js"):
        score += 100

    if "main.js" in value:
        score += 40

    if "chunk" in value:
        score += 30

    if "polyfill" in value:
        score -= 500

    if "favicon" in value:
        score -= 500

    if "robots.txt" in value:
        score -= 500

    if value.endswith(".css"):
        score -= 600

    static_extensions = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )

    if value.endswith(static_extensions):
        score -= 600

    return score


def build_candidate_list(recon_state):
    discovered_targets = recon_state.get(
        "discovered_targets",
        []
    )

    tested_targets = recon_state.get(
        "tested_targets",
        []
    )

    tested_urls = set()

    for target in tested_targets:
        normalized = normalize_tested_target(target)

        if normalized:
            tested_urls.add(normalized)

    candidates = []
    seen = set()

    for index, target in enumerate(
        discovered_targets
    ):
        normalized = normalize_target(target)

        if not normalized:
            continue

        if normalized in tested_urls:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        candidates.append(
            {
                "index": index,
                "target": target,
                "url": normalized,
                "category": classify_target(
                    normalized
                ),
                "priority": target_priority(
                    normalized
                ),
            }
        )

    candidates.sort(
        key=lambda item: item["priority"],
        reverse=True
    )

    return candidates


def format_candidates(candidates):
    return [
        {
            "index": item["index"],
            "target": item["target"],
            "category": item["category"],
            "priority": item["priority"],
        }
        for item in candidates
    ]


def parse_decision(response_text):
    text = response_text.strip()

    try:
        return json.loads(text)

    except json.JSONDecodeError:
        match = re.search(
            r"\{.*\}",
            text,
            re.DOTALL
        )

        if not match:
            raise ValueError(
                "GPT-OSS returned invalid Recon JSON."
            )

        return json.loads(match.group(0))


def fallback_selection(candidates):
    selected = [
        item["index"]
        for item in candidates[
            :MAX_TARGETS_PER_DECISION
        ]
    ]

    return {
        "action": "test",
        "target_indices": selected,
        "reason": (
            "Fallback selection used because "
            "GPT-OSS did not select valid targets."
        ),
    }


def choose_next_targets(recon_state):
    candidates = build_candidate_list(
        recon_state
    )

    print("\nGPT-OSS RECON DECISION")
    print("-" * 40)

    if not candidates:
        decision = {
            "action": "finish",
            "target_indices": [],
            "reason": (
                "No unexplored reconnaissance "
                "targets remain."
            ),
        }

        safe_print(
            json.dumps(
                decision,
                ensure_ascii=True
            )
        )

        return decision

    llm_candidates = candidates[
        :MAX_LLM_CANDIDATES
    ]

    candidate_text = json.dumps(
        format_candidates(
            llm_candidates
        ),
        indent=2,
        ensure_ascii=True
    )

    tested_targets = recon_state.get(
        "tested_targets",
        []
    )

    observations = recon_state.get(
        "observations",
        []
    )

    prompt = f"""
Target:

{recon_state.get(
    "target_url",
    "http://localhost:3000"
)}

There are currently
{len(candidates)}
meaningful unexplored targets.

You MUST select targets.

Candidate targets:

{candidate_text}

Already tested:

{json.dumps(
    tested_targets[-20:],
    indent=2,
    ensure_ascii=True
)}

Recent observations:

{json.dumps(
    observations[-10:],
    indent=2,
    ensure_ascii=True
)}

Choose up to 5 targets.

IMPORTANT:

If candidates exist, DO NOT return finish.

Return ONLY JSON:

{{
    "action": "test",
    "target_indices": [0, 1, 2],
    "reason": "short explanation"
}}
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
            ),
        ]
    )

    try:
        decision = parse_decision(
            response.content
        )

    except Exception:
        decision = fallback_selection(
            candidates
        )

    safe_print(
        json.dumps(
            decision,
            indent=2,
            ensure_ascii=True
        )
    )

    action = decision.get("action")

    target_indices = decision.get(
        "target_indices",
        []
    )

    if not isinstance(
        target_indices,
        list
    ):
        target_indices = []

    valid_candidate_indices = {
        item["index"]
        for item in llm_candidates
    }

    valid_indices = []

    for index in target_indices:
        try:
            index = int(index)
        except (
            TypeError,
            ValueError
        ):
            continue

        if index not in valid_candidate_indices:
            continue

        if index in valid_indices:
            continue

        valid_indices.append(index)

        if len(valid_indices) >= MAX_TARGETS_PER_DECISION:
            break

    if action == "finish":
        print(
            "[RECON] GPT attempted to finish "
            "while targets remain."
        )

        decision = fallback_selection(
            candidates
        )

        safe_print(
            json.dumps(
                decision,
                indent=2,
                ensure_ascii=True
            )
        )

        return decision

    if not valid_indices:
        print(
            "[RECON] GPT returned no valid targets."
        )

        decision = fallback_selection(
            candidates
        )

        safe_print(
            json.dumps(
                decision,
                indent=2,
                ensure_ascii=True
            )
        )

        return decision

    return {
        "action": "test",
        "target_indices": valid_indices,
        "reason": decision.get(
            "reason",
            "Adaptive reconnaissance target selection."
        ),
    }


def update_recon_state(
    recon_state,
    observations=None
):
    if observations is None:
        observations = []

    recon_state.setdefault(
        "discovered_targets",
        []
    )

    recon_state.setdefault(
        "tested_targets",
        []
    )

    recon_state.setdefault(
        "interesting_targets",
        []
    )

    recon_state.setdefault(
        "remaining_targets",
        []
    )

    recon_state.setdefault(
        "observations",
        []
    )

    recon_state.setdefault(
        "technologies",
        []
    )

    recon_state.setdefault(
        "endpoints",
        []
    )

    recon_state.setdefault(
        "forms",
        []
    )

    recon_state.setdefault(
        "parameters",
        []
    )

    for observation in observations:
        if not isinstance(
            observation,
            dict
        ):
            continue

        recon_state["observations"].append(
            observation
        )

        # IMPORTANT:
        # recon_runner wraps the actual result as:
        #
        # observation["result"]["data"]
        #
        # Older callers may provide:
        #
        # observation["data"]
        #
        # Support both formats.

        data = observation.get(
            "data"
        )

        if not isinstance(data, dict):
            result = observation.get(
                "result",
                {}
            )

            if isinstance(result, dict):
                data = result.get(
                    "data",
                    {}
                )

        if not isinstance(data, dict):
            continue

        for key in [
            "technologies",
            "endpoints",
            "forms",
            "parameters",
            "interesting_targets",
        ]:
            values = data.get(
                key,
                []
            )

            if not isinstance(
                values,
                list
            ):
                continue

            for value in values:
                if value not in recon_state[key]:
                    recon_state[key].append(
                        value
                    )

    tested_urls = set()

    for target in recon_state[
        "tested_targets"
    ]:
        normalized = normalize_tested_target(
            target
        )

        if normalized:
            tested_urls.add(
                normalized
            )

    remaining = []
    seen = set()

    for target in recon_state[
        "discovered_targets"
    ]:
        normalized = normalize_target(
            target
        )

        if not normalized:
            continue

        if normalized in tested_urls:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)

        remaining.append(target)

    recon_state[
        "remaining_targets"
    ] = remaining

    recon_state[
        "iteration"
    ] = recon_state.get(
        "iteration",
        0
    ) + 1

    recon_state[
        "completed"
    ] = len(remaining) == 0

    return recon_state


def sanitize_recon_result(result):
    if not isinstance(
        result,
        dict
    ):
        return result

    sensitive_keys = {
        "token",
        "jwt",
        "authorization",
        "cookie",
        "session",
        "access_token",
        "refresh_token",
        "password",
        "authenticated_session",
        "auth_token",
    }

    def clean(value):
        if isinstance(
            value,
            dict
        ):
            output = {}

            for key, item in value.items():
                if (
                    str(key).lower()
                    in sensitive_keys
                ):
                    continue

                output[key] = clean(item)

            return output

        if isinstance(
            value,
            list
        ):
            return [
                clean(item)
                for item in value
            ]

        return value

    return clean(result)