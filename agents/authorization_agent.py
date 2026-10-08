import json
import re

from dotenv import load_dotenv
from groq_key_manager import get_llm


load_dotenv()


llm = get_llm("authorization")


SYSTEM_PROMPT = """
You are an autonomous Authorization Security Specialist.

Your job is to analyze supplied web application targets and identify
potential authorization and access-control weaknesses.

You are operating only against an authorized local testing environment.

Focus on:

- Admin endpoints
- User-specific endpoints
- Profile and account endpoints
- Address endpoints
- Role and permission endpoints
- API endpoints exposing user data
- Endpoints that may require authentication
- Endpoints that may expose privileged functionality
- Differences between authenticated and unauthenticated access

Rules:

1. Only select targets supplied in the candidate list.
2. Never invent targets.
3. Never select an already tested target.
4. Prefer high-value authorization targets.
5. Prefer admin, user, profile, account, address, role, permission,
   and sensitive API endpoints.
6. Do not perform destructive actions.
7. Do not create accounts.
8. Do not modify passwords or user data.
9. Do not expose authentication tokens, cookies, passwords, or secrets.
10. Continue testing while meaningful authorization targets remain.
11. Return valid JSON only.

Your decision format must be:

{
    "action": "test" or "finish",
    "target_indices": [0, 1, 2],
    "reason": "short explanation"
}
"""


AUTHORIZATION_KEYWORDS = {
    "/admin": 1000,
    "/users": 950,
    "/user/": 900,
    "/profile": 850,
    "/account": 850,
    "/address": 800,
    "/permission": 800,
    "/permissions": 800,
    "/role": 800,
    "/roles": 800,
    "/api/users": 950,
    "/api/address": 850,
    "/api/profile": 850,
    "/rest/admin": 1000,
    "/rest/user": 900,
}


def normalize_url(target):
    if isinstance(target, dict):
        return str(target.get("url", "")).strip()

    return str(target).strip()


def is_authorization_target(target):
    url = normalize_url(target).lower()

    if not url:
        return False

    keywords = (
        "/admin",
        "/users",
        "/user/",
        "/profile",
        "/account",
        "/address",
        "/permission",
        "/permissions",
        "/role",
        "/roles",
    )

    if any(keyword in url for keyword in keywords):
        return True

    if "/api/" in url:
        return True

    if "/rest/" in url:
        return True

    return False


def get_priority(target):
    url = normalize_url(target).lower()

    priority = 100

    for keyword, value in AUTHORIZATION_KEYWORDS.items():
        if keyword in url:
            priority = max(priority, value)

    if "/api/" in url:
        priority += 100

    if "/rest/" in url:
        priority += 100

    if "admin" in url:
        priority += 150

    if "user" in url:
        priority += 75

    if "profile" in url or "account" in url:
        priority += 60

    if "address" in url:
        priority += 50

    return priority


def build_authorization_candidates(authz_state):
    discovered_targets = authz_state.get(
        "discovered_targets",
        []
    )

    tested_targets = authz_state.get(
        "tested_targets",
        []
    )

    tested_urls = set()

    for item in tested_targets:
        url = normalize_url(item)

        if url:
            tested_urls.add(url.rstrip("/"))

    candidates = []
    seen_urls = set()

    for target in discovered_targets:
        url = normalize_url(target)

        if not url:
            continue

        normalized_url = url.rstrip("/")

        if normalized_url in tested_urls:
            continue

        if normalized_url in seen_urls:
            continue

        if not is_authorization_target(target):
            continue

        seen_urls.add(normalized_url)

        if isinstance(target, dict):
            candidate = dict(target)
        else:
            candidate = {
                "type": "endpoint",
                "url": url,
            }

        candidate["_priority"] = get_priority(candidate)

        candidates.append(candidate)

    candidates.sort(
        key=lambda item: item.get("_priority", 0),
        reverse=True
    )

    return candidates


def format_candidates(candidates):
    lines = []

    for index, target in enumerate(candidates):
        clean_target = dict(target)

        clean_target.pop("_priority", None)

        lines.append(
            f"{index}: {json.dumps(clean_target, ensure_ascii=False)}"
        )

    return "\n".join(lines)


def parse_decision(response_text):
    try:
        match = re.search(
            r"\{.*\}",
            response_text,
            re.DOTALL
        )

        if not match:
            return None

        decision = json.loads(match.group(0))

        if not isinstance(decision, dict):
            return None

        action = decision.get("action")

        if action not in {"test", "finish"}:
            return None

        if action == "test":
            target_indices = decision.get(
                "target_indices",
                []
            )

            if not isinstance(target_indices, list):
                return None

            target_indices = [
                index
                for index in target_indices
                if isinstance(index, int)
            ]

            return {
                "action": "test",
                "target_indices": target_indices,
                "reason": str(
                    decision.get(
                        "reason",
                        "Authorization targets selected."
                    )
                ),
            }

        return {
            "action": "finish",
            "target_indices": [],
            "reason": str(
                decision.get(
                    "reason",
                    "No meaningful authorization targets remain."
                )
            ),
        }

    except Exception:
        return None


def choose_authorization_target(authz_state):
    candidates = build_authorization_candidates(
        authz_state
    )

    if not candidates:
        return {
            "action": "finish",
            "targets": [],
            "reason": "No unexplored authorization targets remain.",
        }

    BATCH_SIZE = 5
    max_candidates = 20

    llm_candidates = candidates[:max_candidates]

    candidate_text = format_candidates(
        llm_candidates
    )

    prompt = f"""
{SYSTEM_PROMPT}

Current authorization assessment state:

Targets discovered:
{len(authz_state.get("discovered_targets", []))}

Targets already tested:
{len(authz_state.get("tested_targets", []))}

Targets remaining:
{len(candidates)}

Candidate authorization targets:

{candidate_text}

Select up to {BATCH_SIZE} of the most useful authorization targets
to test next.

Prioritize:
- admin endpoints
- user-specific endpoints
- profile/account endpoints
- address endpoints
- privileged APIs
- sensitive user-data APIs

Do not select already tested targets.

Return JSON only:

{{
    "action": "test",
    "target_indices": [0, 1, 2, 3, 4],
    "reason": "short explanation"
}}

If no useful targets remain:

{{
    "action": "finish",
    "target_indices": [],
    "reason": "short explanation"
}}
"""

    response = llm.invoke(prompt)

    response_text = getattr(
        response,
        "content",
        str(response)
    )

    decision = parse_decision(
        response_text
    )

    if decision is None:
        selected_targets = llm_candidates[:BATCH_SIZE]

        return {
            "action": "test",
            "targets": selected_targets,
            "reason": "Fallback to highest-priority authorization targets.",
        }

    if decision["action"] == "finish":
        return {
            "action": "finish",
            "targets": [],
            "reason": decision["reason"],
        }

    selected_targets = []

    for index in decision.get(
        "target_indices",
        []
    )[:BATCH_SIZE]:

        if index < 0 or index >= len(llm_candidates):
            continue

        target = llm_candidates[index]

        clean_target = dict(target)

        clean_target.pop(
            "_priority",
            None
        )

        selected_targets.append(
            clean_target
        )

    if not selected_targets:
        selected_targets = [
            dict(target)
            for target in llm_candidates[:BATCH_SIZE]
        ]

        for target in selected_targets:
            target.pop(
                "_priority",
                None
            )

    return {
        "action": "test",
        "targets": selected_targets,
        "reason": decision.get(
            "reason",
            "Authorization targets selected by GPT-OSS."
        ),
    }


def update_authorization_state(
    authz_state,
    target,
    result,
    reason
):
    url = normalize_url(target)

    if url:
        existing_urls = {
            normalize_url(item).rstrip("/")
            for item in authz_state.get(
                "tested_targets",
                []
            )
        }

        if url.rstrip("/") not in existing_urls:
            authz_state.setdefault(
                "tested_targets",
                []
            ).append(url)

    observation = {
        "target": url,
        "reason": reason,
        "result": result,
    }

    authz_state.setdefault(
        "observations",
        []
    ).append(observation)

    if isinstance(result, dict):
        data = result.get("data", result)

        if isinstance(data, dict):
            if data.get("vulnerable") is True:
                authz_state.setdefault(
                    "findings",
                    []
                ).append({
                    "target": url,
                    "detail": data.get(
                        "detail",
                        "Authorization weakness detected."
                    ),
                    "data": data,
                })

    remaining = []

    tested_urls = {
        normalize_url(item).rstrip("/")
        for item in authz_state.get(
            "tested_targets",
            []
        )
    }

    seen_urls = set()

    for item in authz_state.get(
        "discovered_targets",
        []
    ):
        item_url = normalize_url(item)

        if not item_url:
            continue

        normalized_url = item_url.rstrip("/")

        if normalized_url in tested_urls:
            continue

        if normalized_url in seen_urls:
            continue

        if not is_authorization_target(item):
            continue

        seen_urls.add(normalized_url)

        remaining.append(item)

    authz_state["remaining_targets"] = remaining

    authz_state["iteration"] = (
        authz_state.get("iteration", 0) + 1
    )

    return authz_state


def finish_authorization_state(authz_state):
    authz_state["completed"] = True

    authz_state["remaining_targets"] = [
        target
        for target in authz_state.get(
            "remaining_targets",
            []
        )
        if normalize_url(target)
    ]

    return authz_state


def initialize_authorization_state(recon_state):
    attack_surface = recon_state.get(
        "attack_surface",
        {}
    )

    discovered = []

    authorization_targets = attack_surface.get(
        "authorization",
        []
    )

    user_targets = attack_surface.get(
        "user_endpoints",
        []
    )

    for target in authorization_targets:
        if isinstance(target, dict):
            discovered.append(dict(target))
        else:
            discovered.append({
                "type": "endpoint",
                "url": target,
            })

    for target in user_targets:
        if isinstance(target, dict):
            discovered.append(dict(target))
        else:
            discovered.append({
                "type": "endpoint",
                "url": target,
            })

    unique = []
    seen = set()

    for target in discovered:
        url = normalize_url(target)

        if not url:
            continue

        normalized_url = url.rstrip("/")

        if normalized_url in seen:
            continue

        seen.add(normalized_url)
        unique.append(target)

    return {
        "discovered_targets": unique,
        "tested_targets": [],
        "remaining_targets": unique.copy(),
        "observations": [],
        "findings": [],
        "iteration": 0,
        "completed": False,
    }


def sanitize_authorization_result(result):
    if not isinstance(result, dict):
        return result

    sensitive_keys = {
        "token",
        "jwt",
        "authorization",
        "cookie",
        "cookies",
        "session",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "auth_token",
    }

    def sanitize(value):
        if isinstance(value, dict):
            cleaned = {}

            for key, item in value.items():
                if str(key).lower() in sensitive_keys:
                    cleaned[key] = "[REDACTED]"
                else:
                    cleaned[key] = sanitize(item)

            return cleaned

        if isinstance(value, list):
            return [
                sanitize(item)
                for item in value
            ]

        return value

    return sanitize(result)