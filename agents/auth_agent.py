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
You are an autonomous Authentication Security Specialist.

Your job is to select the most useful authentication target from the supplied candidate list.

Rules:

1. Only select targets from the supplied list.
2. Never invent a target.
3. Never select an already tested target.
4. Prefer:
   - login
   - authentication
   - registration
   - password reset
   - password change
   - security questions
   - security answers
   - whoami
   - session endpoints
   - authentication details
5. Continue testing while meaningful authentication targets remain.
6. Only return finish when there are NO candidates left.
7. Do not request, reveal, or output passwords, JWTs, cookies, session tokens, or other secrets.

Return ONLY valid JSON:

{
    "action": "test" or "finish",
    "target_index": integer,
    "reason": "short explanation"
}
"""


AUTH_KEYWORDS = [
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/sign-in",
    "/sign-up",
    "/authentication",
    "/authenticate",
    "/auth",
    "/whoami",
    "/session",
    "/password",
    "/reset-password",
    "/change-password",
    "/forgot-password",
    "/security-question",
    "/security-questions",
    "/security-answer",
    "/security-answers",
    "/authentication-details",
    "/saveloginip",
    "/rest/user"
]


def is_auth_target(target):
    url = str(target.get("url", "")).lower()

    return any(
        keyword in url
        for keyword in AUTH_KEYWORDS
    )


def build_auth_candidates(auth_state):
    candidates = []

    seen = set()

    tested_urls = set()

    for item in auth_state.get("tested_targets", []):
        if isinstance(item, dict):
            url = str(item.get("url", "")).strip()
        else:
            url = str(item).strip()

        if url:
            tested_urls.add(url)

    for target in auth_state.get("discovered_targets", []):
        if not isinstance(target, dict):
            continue

        url = str(target.get("url", "")).strip()

        if not url:
            continue

        if url in tested_urls:
            continue

        if url in seen:
            continue

        if not is_auth_target(target):
            continue

        seen.add(url)

        lower_url = url.lower()

        priority = 100

        if "/login" in lower_url:
            priority += 1000

        if "/authenticate" in lower_url or "/authentication" in lower_url:
            priority += 900

        if "/register" in lower_url or "/signup" in lower_url:
            priority += 800

        if "/password" in lower_url:
            priority += 700

        if "/security-question" in lower_url:
            priority += 650

        if "/security-answer" in lower_url:
            priority += 600

        if "/whoami" in lower_url:
            priority += 500

        if "/session" in lower_url:
            priority += 450

        if "/rest/user" in lower_url:
            priority += 300

        candidate = {
            "url": url,
            "type": target.get("type", "endpoint"),
            "method": target.get("method", "GET"),
            "priority": priority
        }

        candidates.append(candidate)

    candidates.sort(
        key=lambda x: x["priority"],
        reverse=True
    )

    return candidates


def parse_decision(response_text):
    try:
        return json.loads(response_text)
    except Exception:
        pass

    match = re.search(
        r"\{.*\}",
        response_text,
        re.DOTALL
    )

    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    return None


def normalize_decision(decision):
    if not isinstance(decision, dict):
        return {
            "action": "finish",
            "target_index": -1,
            "reason": "Invalid model decision"
        }

    action = str(
        decision.get("action", "finish")
    ).lower().strip()

    try:
        target_index = int(
            decision.get("target_index", -1)
        )
    except Exception:
        target_index = -1

    reason = str(
        decision.get("reason", "")
    ).strip()

    if action not in {"test", "finish"}:
        action = "test"

    return {
        "action": action,
        "target_index": target_index,
        "reason": reason
    }


def choose_auth_target(auth_state):
    candidates = build_auth_candidates(auth_state)

    if not candidates:
        return {
            "action": "finish",
            "target_index": -1,
            "target": None,
            "reason": "No remaining authentication targets"
        }

    MAX_LLM_CANDIDATES = 20

    llm_candidates = candidates[:MAX_LLM_CANDIDATES]

    candidate_text = "\n".join(
        f"{i}: {candidate['url']} "
        f"[type={candidate['type']}, method={candidate['method']}]"
        for i, candidate in enumerate(llm_candidates)
    )

    prompt = f"""
{SYSTEM_PROMPT}

Remaining authentication targets:

{candidate_text}

Select the next target.

Remember:

- If targets remain, you MUST choose action "test".
- You may NOT return "finish" while targets remain.

Return only JSON.
"""

    try:
        response = llm.invoke(prompt)

        response_text = getattr(
            response,
            "content",
            str(response)
        )

        decision = parse_decision(response_text)
        decision = normalize_decision(decision)

    except Exception as e:
        decision = {
            "action": "test",
            "target_index": 0,
            "reason": f"LLM error fallback: {type(e).__name__}"
        }

    if decision["action"] == "finish":
        decision["action"] = "test"
        decision["target_index"] = 0
        decision["reason"] = (
            "Authentication targets remain, "
            "so testing must continue."
        )

    if (
        decision["target_index"] < 0
        or decision["target_index"] >= len(llm_candidates)
    ):
        decision["target_index"] = 0
        decision["reason"] = (
            "Invalid model index; selected highest-priority target."
        )

    decision["target"] = llm_candidates[
        decision["target_index"]
    ]

    print("\nGPT-OSS AUTH DECISION")

    print({
        "action": decision["action"],
        "target_index": decision["target_index"],
        "reason": decision["reason"]
    })

    return decision


def sanitize_auth_result(result):
    if not isinstance(result, dict):
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
        "passwd",
        "secret",
        "credential",
        "credentials"
    }

    cleaned = {}

    for key, value in result.items():
        key_lower = str(key).lower()

        if any(
            sensitive in key_lower
            for sensitive in sensitive_keys
        ):
            continue

        if isinstance(value, dict):
            cleaned[key] = sanitize_auth_result(value)

        elif isinstance(value, list):
            cleaned[key] = [
                sanitize_auth_result(item)
                if isinstance(item, dict)
                else item
                for item in value
            ]

        else:
            cleaned[key] = value

    return cleaned


def update_auth_state(
    auth_state,
    target,
    result,
    decision_reason=""
):
    if not isinstance(target, dict):
        return auth_state

    target_url = str(
        target.get("url", "")
    ).strip()

    if not target_url:
        return auth_state

    tested_urls = set()

    for item in auth_state.get("tested_targets", []):
        if isinstance(item, dict):
            url = str(
                item.get("url", "")
            ).strip()
        else:
            url = str(item).strip()

        if url:
            tested_urls.add(url)

    if target_url not in tested_urls:
        auth_state.setdefault(
            "tested_targets",
            []
        ).append(target_url)

    safe_result = sanitize_auth_result(result)

    observation = {
        "target": target_url,
        "reason": decision_reason,
        "result": safe_result
    }

    auth_state.setdefault(
        "observations",
        []
    ).append(observation)

    if isinstance(result, dict):

        if result.get("authenticated") is True:
            auth_state["authenticated"] = True

        if result.get("session_created") is True:
            auth_state["authenticated"] = True

        if result.get("finding"):
            auth_state.setdefault(
                "findings",
                []
            ).append(
                sanitize_auth_result(
                    result["finding"]
                )
            )

    tested_set = set(
        auth_state.get(
            "tested_targets",
            []
        )
    )

    remaining = []

    seen = set()

    for item in auth_state.get(
        "discovered_targets",
        []
    ):
        if not isinstance(item, dict):
            continue

        url = str(
            item.get("url", "")
        ).strip()

        if not url:
            continue

        if url in tested_set:
            continue

        if url in seen:
            continue

        if not is_auth_target(item):
            continue

        seen.add(url)

        remaining.append(item)

    auth_state["remaining_targets"] = remaining

    auth_state["iteration"] = (
        auth_state.get("iteration", 0) + 1
    )

    return auth_state


def initialize_auth_state(recon_state):
    discovered = []

    attack_surface = recon_state.get(
        "attack_surface",
        {}
    )

    surface_targets = attack_surface.get(
        "auth_endpoints",
        []
    )

    auth_endpoints = recon_state.get(
        "auth_endpoints",
        []
    )

    all_targets = []

    if isinstance(surface_targets, list):
        all_targets.extend(surface_targets)

    if isinstance(auth_endpoints, list):
        all_targets.extend(auth_endpoints)

    seen = set()

    for target in all_targets:

        if not isinstance(target, dict):
            continue

        url = str(
            target.get("url", "")
        ).strip()

        if not url:
            continue

        if url in seen:
            continue

        seen.add(url)

        discovered.append({
            "url": url,
            "type": target.get(
                "type",
                "endpoint"
            ),
            "method": target.get(
                "method",
                "GET"
            )
        })

    auth_state = {
        "discovered_targets": discovered,
        "tested_targets": [],
        "remaining_targets": discovered.copy(),
        "observations": [],
        "findings": [],
        "authenticated": False,
        "iteration": 0,
        "completed": False
    }

    return auth_state


def finish_auth_state(auth_state):
    auth_state["completed"] = (
        len(
            auth_state.get(
                "remaining_targets",
                []
            )
        ) == 0
    )

    return auth_state