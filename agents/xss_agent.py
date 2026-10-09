import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from dotenv import load_dotenv
from groq_key_manager import get_llm

from tools.xss_tools import execute_xss_test

load_dotenv()

llm = get_llm("xss")

# How many candidates to present to the LLM in a single decision prompt.
MAX_XSS_TARGETS = 20
# How many targets the LLM may pick (and we queue) per decision.
BATCH_SIZE = 5
# LLM-decision budget (cost control). Coverage continues locally after this.
MAX_LLM_CALLS = 4
# Hard safety cap on the total number of expanded candidates.
CANDIDATE_POOL_LIMIT = 300


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
                parsed.fragment
            )
        )

    except Exception:
        return str(url).strip().rstrip("/")


def _target_identity(target):
    url = _normalize_url(_target_url(target))
    parameter = _target_parameter(target)
    method = _target_method(target)
    target_type = target.get("xss_target_type", "")
    index = target.get("index")
    selector = target.get("selector") or target.get("input_selector") or ""

    return (
        method,
        url,
        parameter,
        target_type,
        index,
        selector
    )


from urllib.parse import urlsplit

def _is_static_target(target):
    url = _target_url(target).lower()
    path = urlsplit(url).path
    static_extensions = (
        ".css", ".js", ".mjs",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".webm", ".pdf"
    )
    return path.endswith(static_extensions)

from urllib.parse import urlparse, parse_qs

def _expand_xss_targets(target):
    url = _target_url(target)
    if not url or _is_static_target(target):
        return []
    
    expanded = []
    
    explicit_type = _target_type(target)
    index = target.get("index")
    selector = target.get("selector") or target.get("input_selector")
    
    if (
        explicit_type == "input"
        or (
            isinstance(index, int)
            and not isinstance(index, bool)
            and index >= 0
        )
        or selector
    ):
        item = dict(target)
        item["xss_target_type"] = "input"
        expanded.append(item)
        
    parsed = urlparse(url)
    
    for param in parse_qs(parsed.query, keep_blank_values=True):
        item = dict(target)
        item["xss_target_type"] = "url_parameter"
        item["parameter"] = param
        expanded.append(item)
        
    if parsed.fragment:
        fragment_str = parsed.fragment.lstrip("#")
        fragment_route = urlparse(fragment_str)
        frag_query = fragment_route.query
        if not frag_query and "?" in fragment_str:
            frag_query = fragment_str.split("?", 1)[1]
        for param in parse_qs(frag_query, keep_blank_values=True):
            item = dict(target)
            item["xss_target_type"] = "fragment"
            item["parameter"] = param
            expanded.append(item)
        
    if explicit_type == "dom" or target.get("dom_source") or target.get("dom_sink"):
        item = dict(target)
        item["xss_target_type"] = "dom"
        expanded.append(item)
        
    if explicit_type == "stored":
        item = dict(target)
        item["xss_target_type"] = "stored"
        expanded.append(item)
        
    return expanded


def _target_score(target):
    url = _target_url(target).lower()
    xss_type = target.get("xss_target_type", "")
    score = 0

    # Static assets have no injectable surface, EXCEPT a JS asset that has been
    # promoted to a DOM source/sink analysis candidate (xss_target_type="dom").
    if _is_static_target(target) and xss_type != "dom":
        return -100

    # 1. Explicit browser inputs with valid index/selector
    if xss_type == "input":
        score += 50
    # 2. Query parameters, including empty values
    elif xss_type == "url_parameter":
        score += 40
    # 3. SPA fragment parameters
    elif xss_type == "fragment":
        score += 35
    # 4. Explicit DOM source/sink targets
    elif xss_type == "dom":
        score += 30
    # 5. Stored-XSS workflows
    elif xss_type == "stored":
        score += 25

    if target.get("parameter"):
        score += 10

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
            break

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

def _build_candidate_pool(state):
    """
    Expand the immutable reconnaissance set (``discovered_targets``) into a
    stable, deduplicated pool of individual XSS *candidates* (inputs, URL
    parameters, fragments, DOM/JS assets).

    This is built once and cached in ``xss_state["candidate_pool"]``.
    ``discovered_targets`` (the raw recon set) is NEVER mutated, so the three
    kinds of count stay separate:
      - raw endpoints      -> len(discovered_targets)
      - XSS candidates     -> len(candidate_pool)
      - analyzed candidates-> len(tested_targets) + len(skipped_targets)
    """
    xss_state = state["xss_state"]

    if xss_state.get("_candidate_pool_built"):
        return xss_state.setdefault("candidate_pool", [])

    discovered_targets = xss_state.get("discovered_targets", [])

    pool = []

    for target in discovered_targets:
        if not _target_url(target):
            continue

        # Static JavaScript assets are routed to the DOM source/sink analyzer
        # as a "dom" candidate rather than silently dropped.
        if _is_static_js_target(target):
            dom_candidate = (
                dict(target)
                if isinstance(target, dict)
                else {"url": _target_url(target)}
            )
            dom_candidate["xss_target_type"] = "dom"
            pool.append(dom_candidate)
            continue

        # Other static assets (CSS, images, fonts) have no injectable surface.
        if _is_static_target(target):
            continue

        pool.extend(_expand_xss_targets(target))

    pool = _deduplicate_targets(pool)
    pool.sort(key=_target_score, reverse=True)
    pool = pool[:CANDIDATE_POOL_LIMIT]

    xss_state["candidate_pool"] = pool
    xss_state["_candidate_pool_built"] = True

    return pool


def _prepare_candidate_targets(state):
    """Return pool candidates that have not yet been tested or skipped."""
    xss_state = state["xss_state"]

    pool = _build_candidate_pool(state)

    processed_keys = {
        _target_identity(target)
        for target in (
            xss_state.get("tested_targets", [])
            + xss_state.get("skipped_targets", [])
        )
    }

    return [
        target
        for target in pool
        if _target_identity(target) not in processed_keys
    ]


def _pool_index(pool, target):
    """Index of a candidate object within the pool, or None."""
    try:
        return pool.index(target)
    except ValueError:
        return None


def choose_next_target(state):
    """
    Select the next XSS candidate to test.

    The returned ``target_index`` is an index into
    ``xss_state["candidate_pool"]`` (the expanded candidate set), NOT into the
    raw reconnaissance set ``discovered_targets`` (which is never mutated).

    The LLM prioritizes a batch; the runner tests one candidate at a time, so
    we keep a local batch queue to avoid an LLM call per target. When the LLM
    budget is exhausted (or the LLM finishes prematurely), selection continues
    deterministically from the remaining candidates so coverage is not cut off.
    """
    xss_state = state["xss_state"]

    pool = _build_candidate_pool(state)
    batch_queue = xss_state.setdefault("_batch_queue", [])

    # 1. Serve any candidate already queued from a previous batch decision.
    while batch_queue:
        target = batch_queue.pop(0)
        idx = _pool_index(pool, target)
        if idx is None:
            continue
        return {
            "action": "test",
            "target_index": idx,
            "reason": "Selected from the current XSS candidate batch.",
        }

    candidates = _prepare_candidate_targets(state)

    if not candidates:
        return {
            "action": "finish",
            "target_index": None,
            "reason": "No unexplored XSS candidates remain.",
        }

    llm_calls = xss_state.get("_llm_calls", 0)

    def _serve_locally(reason):
        batch = candidates[:BATCH_SIZE]
        xss_state["_batch_queue"] = batch[1:]
        return {
            "action": "test",
            "target_index": _pool_index(pool, batch[0]),
            "reason": reason,
        }

    # 2. LLM budget exhausted: keep draining candidates deterministically.
    if llm_calls >= MAX_LLM_CALLS:
        return _serve_locally(
            "Local deterministic selection (LLM decision budget reached)."
        )

    # 3. Ask the LLM to prioritize, from a capped presentation list.
    presented = candidates[:MAX_XSS_TARGETS]

    compact_candidates = [
        {
            "index": index,
            "url": _target_url(target),
            "type": _target_type(target),
            "parameter": _target_parameter(target),
            "method": _target_method(target),
        }
        for index, target in enumerate(presented)
    ]

    compact_observations = xss_state.get("observations", [])[-5:]

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
                ("human", prompt),
            ]
        )
        decision = parse_decision(response.content)

    except Exception as e:
        print(f"[XSS] LLM decision failed: {e}")
        return _serve_locally("Local fallback target selection.")

    # The LLM must not finish while eligible candidates remain.
    if decision.get("action") == "finish":
        print(
            "[XSS] LLM finished while eligible candidates remain. "
            "Continuing with local selection."
        )
        return _serve_locally(
            "Local candidate fallback after premature LLM finish."
        )

    indices = decision.get("target_indices", [])
    if not isinstance(indices, list):
        indices = []

    selected = []
    for index in indices[:BATCH_SIZE]:
        if not isinstance(index, int):
            continue
        if index < 0 or index >= len(presented):
            continue
        target = presented[index]
        if target not in selected:
            selected.append(target)

    if not selected:
        selected = presented[:BATCH_SIZE]

    first_target = selected[0]
    xss_state["_batch_queue"] = selected[1:]

    return {
        "action": "test",
        "target_index": _pool_index(pool, first_target),
        "reason": decision.get("reason", "Selected by the XSS specialist."),
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

    data = result.get(
        "data",
        {}
    )
    
    status = data.get("test_status", "inconclusive")
    
    if status == "skipped":
        if target not in xss_state.get("skipped_targets", []):
            xss_state.setdefault("skipped_targets", []).append(target)
    else:
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

    status = data.get("test_status", "inconclusive")

    if status == "potential":
        # Detection-only lead (e.g. static DOM source/sink analysis).
        # Recorded as a potential/unverified finding with its evidence, NOT
        # as a confirmed vulnerability.
        potential = xss_state.setdefault("potential_findings", [])
        record = {
            "target": target,
            "endpoint": data.get("tested_endpoint") or _target_url(target),
            "vulnerability_type": "Potential DOM-based XSS",
            "status": "potential",
            "confirmation": "Not established by static analysis alone.",
            "detail": data.get("detail", ""),
            "evidence": data.get("evidence", {}),
            "sources": data.get("sources", []),
            "sinks": data.get("sinks", []),
        }
        if not any(
            _target_identity(p.get("target")) == _target_identity(target)
            for p in potential
            if isinstance(p, dict)
        ):
            potential.append(record)
    elif status == "inconclusive":
        xss_state.setdefault(
            "inconclusive_targets", []
        ).append({
            "target": target,
            "detail": data.get("detail", "")
        })
    elif status == "skipped":
        pass
    elif data.get("confirmed") is True:
        confirmed = xss_state.setdefault(
            "confirmed_vulnerabilities", []
        )
        if target not in confirmed:
            confirmed.append(target)
    elif data.get("suspected") is True:
        if target not in xss_state["successful_targets"]:
            xss_state["successful_targets"].append(target)


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


def _is_static_js_target(target):
    url = _target_url(target).lower()
    path = urlsplit(url).path
    if path.endswith((".js", ".mjs")):
        return True
    if _target_type(target) == "js_assets" or (isinstance(target, dict) and target.get("category") == "js_assets"):
        return True
    return False


def _is_non_script_static_target(target):
    url = _target_url(target).lower()
    path = urlsplit(url).path
    non_script_extensions = (
        ".css",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".webm", ".pdf", ".txt", ".map"
    )
    return path.endswith(non_script_extensions)


def _has_identifiable_inputs(target):
    if not isinstance(target, dict):
        return False
    # If explicit XSS candidate types are already assigned
    if target.get("xss_target_type") in {"input", "url_parameter", "fragment", "dom", "stored"}:
        return True
    # If _expand_xss_targets produces valid candidates
    if _expand_xss_targets(target):
        return True
    # If target has parameter/inputs properties
    if target.get("parameter"):
        return True
    if target.get("parameters") and isinstance(target.get("parameters"), list) and len(target["parameters"]) > 0:
        return True
    if target.get("inputs") and isinstance(target.get("inputs"), list) and len(target["inputs"]) > 0:
        return True
    if target.get("body_params") or target.get("query_params"):
        return True
    if target.get("selector") or target.get("input_selector"):
        return True
    if isinstance(target.get("index"), int) and not isinstance(target.get("index"), bool) and target.get("index") >= 0:
        return True
    if target.get("dom_source") or target.get("dom_sink"):
        return True
    # Check if URL query or fragment has parameters
    url = _target_url(target)
    if url:
        parsed = urlparse(url)
        if parse_qs(parsed.query, keep_blank_values=True):
            return True
        if parsed.fragment and ("?" in parsed.fragment or parse_qs(parsed.fragment.lstrip("#"), keep_blank_values=True)):
            return True
    return False


def _is_target_in_list(target, target_list):
    """
    Check if a target is already recorded in a list (handling dict wrapper with 'target' key).
    """
    target_id = _target_identity(target)
    target_url = _target_url(target)
    for item in target_list:
        if isinstance(item, dict):
            entry_target = item.get("target") if ("target" in item and isinstance(item["target"], (dict, str))) else item
            if _target_identity(entry_target) == target_id:
                return True
            if _target_url(entry_target) == target_url and _target_parameter(entry_target) == _target_parameter(target):
                return True
        elif item == target:
            return True
    return False


def _is_target_in_targets(target, target_list):
    target_id = _target_identity(target)
    for item in target_list:
        if item == target:
            return True
        if isinstance(item, dict) and _target_identity(item) == target_id:
            return True
    return False


def classify_unexpandable_targets(state):
    """
    Classify targets that cannot currently produce a test candidate.
    Distinguishes:
    - Static JS assets requiring DOM source/sink analysis -> unclassified
    - Targets with identifiable inputs -> preserved in queue as valid candidates
    - Targets with genuinely no supported testing method -> skipped
    - Targets that remain unresolved -> unclassified
    """
    xss_state = state.get("xss_state")
    if not isinstance(xss_state, dict):
        return

    discovered = xss_state.get("discovered_targets", [])
    tested = xss_state.get("tested_targets", [])
    skipped = xss_state.setdefault("skipped_targets", [])
    unclassified = xss_state.setdefault("unclassified_targets", [])
    remaining = xss_state.get("remaining_targets", list(discovered))

    new_remaining = []

    for target in list(remaining):
        # Already finalized targets are ignored
        if _is_target_in_targets(target, tested) or _is_target_in_targets(target, skipped):
            continue

        # 1. Valid candidates with identifiable user-controlled inputs:
        # Kept in queue, not marked unclassified, not discarded
        if _has_identifiable_inputs(target):
            new_remaining.append(target)
            continue

        # 2. Static JavaScript assets:
        # Requires DOM source/sink analysis; not counted as tested
        if _is_static_js_target(target):
            if not _is_target_in_list(target, unclassified):
                unclassified.append({
                    "target": target,
                    "status": "unclassified",
                    "detail": "Static asset requires DOM source/sink analysis; not directly injectable.",
                    "category": "static_js"
                })
            new_remaining.append(target)
            continue

        # 3. Targets that genuinely have no supported testing method:
        # e.g., non-script static assets (images, stylesheets, fonts, audio/video)
        if _is_non_script_static_target(target):
            if not _is_target_in_targets(target, skipped):
                skipped.append(target)
            xss_state.setdefault("observations", []).append({
                "target": target,
                "reason": "Skipped: no supported XSS testing method for non-script static asset.",
                "vulnerable": False,
                "detail": "Static non-script asset without injectable input surface."
            })
            continue

        # 4. Targets that remain unresolved and should stay unclassified:
        # e.g., API endpoints without identifiable inputs
        if not _is_target_in_list(target, unclassified):
            unclassified.append({
                "target": target,
                "status": "unclassified",
                "detail": "No supported XSS input, parameter, or DOM target identified.",
                "category": "unresolved_endpoint"
            })
        new_remaining.append(target)

    xss_state["remaining_targets"] = new_remaining