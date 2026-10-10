import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

import json
import re

from dotenv import load_dotenv
from groq_key_manager import get_llm

from state import initial_state
from modules.attack_graph import AttackGraph

from agents.recon_runner import run_recon_specialist
from agents.auth_runner import run_auth_specialist
from agents.sqli_runner import run_sqli_specialist
from agents.idor_runner import run_idor_specialist
from agents.authorization_runner import run_authorization_specialist

from agents.xss_agent import (
    choose_next_target,
    test_selected_target,
    _build_candidate_pool,
    _target_identity,
    classify_unexpandable_targets,
)

from modules.risk_engine import analyze_all


load_dotenv()


llm = get_llm("orchestrator")


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


def _redact_chain_data(chain_data):
    """Return a copy of chain_data with the authenticated session/token removed."""
    redacted = dict(chain_data)
    for key in (
        "authenticated_session",
        "auth_session",
        "session",
        "token",
        "auth_token",
        "access_token",
        "jwt",
        "authorization",
        "cookie",
        "observations",
    ):
        redacted.pop(key, None)
    # Preserve non-sensitive provenance flags.
    if "auth_token_found" in chain_data:
        redacted["auth_token_found"] = bool(chain_data.get("auth_token_found"))
    return redacted


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


import re as _re

_EMAIL_RE = _re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _collect_discovered_emails(state, limit=8):
    """Harvest distinct email addresses already surfaced in findings so the
    auth specialist can prove user enumeration. Local/authorized testing only."""
    if not isinstance(state, dict):
        return []
    try:
        import json as _json
        blob = _json.dumps(state.get("findings", []), default=str)
    except Exception:
        blob = str(state.get("findings", []))

    emails = []
    seen = set()
    for match in _EMAIL_RE.findall(blob):
        email = match.strip().lower()
        if email.endswith(".invalid") or email in seen:
            continue
        seen.add(email)
        emails.append(email)
        if len(emails) >= limit:
            break
    return emails


def update_attack_graph_from_recon(state, recon_result):
    graph = state.get("attack_graph")
    if not graph or not isinstance(recon_result, dict):
        return
    data = recon_result.get("data", {})
    if not isinstance(data, dict):
        return
    attack_surface = data.get("attack_surface", {})
    if not isinstance(attack_surface, dict):
        return
    for category, targets in attack_surface.items():
        if not isinstance(targets, list):
            continue
        for index, target in enumerate(targets):
            if isinstance(target, dict):
                target_data = target
                url = (
                    target.get("url")
                    or target.get("target")
                    or target.get("endpoint")
                )
            elif isinstance(target, str):
                target_data = {"url": target}
                url = target
            else:
                continue

            if not url:
                continue

            node_id = f"{category}:{index}"
            graph.add_node(
                node_id=node_id,
                node_type=category,
                data=target_data
            )


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

    from tools.xss_tools import get_xss_targets, is_local_target

    base_url = state["target_url"].rstrip("/")

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

    raw_candidates = []

    def add_target(target):
        if not isinstance(target, dict):
            return
        item = dict(target)
        raw_url = str(
            item.get("url") or item.get("target") or item.get("endpoint") or ""
        ).strip()
        if not raw_url:
            return
        if not is_local_target(raw_url, base_url):
            return
        raw_candidates.append(item)

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
        if not isinstance(targets, list):
            continue

        for target in targets:
            if isinstance(target, dict):
                add_target(target)
            elif isinstance(target, str):
                add_target({"url": target})

    endpoints = recon_data.get(
        "endpoints",
        []
    )

    if isinstance(endpoints, list):
        for endpoint in endpoints:
            if isinstance(endpoint, dict):
                add_target(endpoint)
            elif isinstance(endpoint, str):
                add_target({"url": endpoint})

    # Seed 1: Browser-discovered form inputs
    try:
        browser_targets = get_xss_targets(state)
        if isinstance(browser_targets, list):
            for bt in browser_targets:
                if isinstance(bt, dict):
                    add_target(bt)
    except Exception as e:
        print(f"[XSS] Browser target discovery warning: {e}")

    # Seed 2: SPA search route
    spa_search_seed = {
        "url": f"{base_url}/#/search?q=",
        "type": "endpoint"
    }
    add_target(spa_search_seed)

    # Seed 3: Stored-XSS review workflow
    stored_reviews_seed = {
        "url": f"{base_url}/rest/products/1/reviews",
        "type": "stored",
        "xss_target_type": "stored"
    }
    add_target(stored_reviews_seed)

    # Deduplicate using target identity preserving input indices and parameters
    unique_targets = []
    seen_identities = set()

    for item in raw_candidates:
        url = str(item.get("url", "")).strip()
        ident = (
            url,
            item.get("type"),
            item.get("xss_target_type"),
            item.get("name"),
            item.get("index"),
            item.get("selector"),
            item.get("parameter"),
        )
        if ident in seen_identities:
            continue
        seen_identities.add(ident)
        unique_targets.append(item)

    state["xss_state"] = {
        # Immutable raw reconnaissance set (used for the "endpoints" count).
        "discovered_targets": unique_targets,
        "recon_targets": list(unique_targets),
        # Expanded candidate pool is built lazily by the XSS agent.
        "candidate_pool": [],
        "_candidate_pool_built": False,
        "tested_targets": [],
        "skipped_targets": [],
        "successful_targets": [],
        "confirmed_vulnerabilities": [],
        "potential_findings": [],
        "remaining_targets": list(
            unique_targets
        ),
        "inconclusive_targets": [],
        "unclassified_targets": [],
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

    # Preserve the immutable raw reconnaissance set for honest counting.
    xss_state.setdefault(
        "recon_targets",
        list(xss_state.get("discovered_targets", []))
    )

    # Build the expanded candidate pool once (inputs, params, fragments, DOM
    # assets). discovered_targets is never mutated by selection.
    candidate_pool = _build_candidate_pool(state)

    print(
        "Raw reconnaissance endpoints:",
        len(xss_state.get("recon_targets", []))
    )
    print(
        "Expanded XSS candidates:",
        len(candidate_pool)
    )

    def _remaining_candidates():
        processed = {
            _target_identity(t)
            for t in (
                xss_state.get("tested_targets", [])
                + xss_state.get("skipped_targets", [])
            )
        }
        return [
            c for c in candidate_pool
            if _target_identity(c) not in processed
        ]

    while _remaining_candidates():

        decision = choose_next_target(state)

        action = decision.get("action")
        target_index = decision.get("target_index")
        reason = decision.get("reason", "")

        if action == "finish":
            break

        if (
            not isinstance(target_index, int)
            or target_index < 0
            or target_index >= len(candidate_pool)
        ):
            # Selection could not point at a valid candidate; stop cleanly.
            break

        target = candidate_pool[target_index]

        # Never re-test a candidate already analyzed.
        processed_ids = {
            _target_identity(t)
            for t in (
                xss_state.get("tested_targets", [])
                + xss_state.get("skipped_targets", [])
            )
        }
        if _target_identity(target) in processed_ids:
            continue

        xss_state["current_target"] = target

        test_selected_target(state, target, reason)

    # Classify raw endpoints that could not produce a testable candidate
    # (static JS awaiting DOM analysis, non-script assets, unresolved APIs).
    classify_unexpandable_targets(state)

    remaining_candidates = _remaining_candidates()
    unclassified = list(xss_state.get("unclassified_targets", []))

    # Completion means every testable candidate was analyzed. Unclassified
    # endpoints (no XSS input surface: param-less APIs, etc.) are accounted
    # for with a reason and do not represent outstanding work, so they do not
    # block completion.
    xss_state["completed"] = len(remaining_candidates) == 0

    recon_count = len(xss_state.get("recon_targets", []))
    candidate_count = len(candidate_pool)
    tested = xss_state.get("tested_targets", [])
    skipped = xss_state.get("skipped_targets", [])
    confirmed_vulnerabilities = list(
        xss_state.get("confirmed_vulnerabilities", [])
    )
    suspected = list(xss_state.get("successful_targets", []))
    potential_findings = list(xss_state.get("potential_findings", []))

    print(
        "\nXSS Specialist Status:",
        "COMPLETED" if xss_state["completed"] else "INCOMPLETE"
    )
    print("Raw reconnaissance endpoints:", recon_count)
    print("Expanded XSS candidates:", candidate_count)
    print("Candidates analyzed (tested):", len(tested))
    print("Candidates skipped:", len(skipped))
    print("Inconclusive:", len(xss_state.get("inconclusive_targets", [])))
    print("Potential (unverified) findings:", len(potential_findings))
    print("Suspected findings:", len(suspected))
    print("Confirmed vulnerabilities:", len(confirmed_vulnerabilities))
    print("Unclassified endpoints:", len(unclassified))
    print("Candidates remaining:", len(remaining_candidates))

    return {
        "specialist": "xss",
        # Raw recon endpoints (stable; no longer inflated by expansion).
        "target_count": recon_count,
        "raw_endpoint_count": recon_count,
        # Distinct expanded XSS candidates.
        "candidate_count": candidate_count,
        # Candidates actually analyzed.
        "tested_count": len(tested),
        "skipped_count": len(skipped),
        "successful_count": len(suspected),
        "confirmed_count": len(confirmed_vulnerabilities),
        "potential_count": len(potential_findings),
        "unclassified_count": len(unclassified),
        "remaining_count": len(remaining_candidates),
        "findings": confirmed_vulnerabilities,
        "potential_findings": potential_findings,
        "suspected_findings": suspected,
        "confirmed_vulnerabilities": confirmed_vulnerabilities,
        "unclassified_targets": unclassified,
        "observations": list(xss_state.get("observations", [])),
        "completed": xss_state["completed"],
    }

def build_decision_prompt(state, shortlist, available):
    """Prompt the orchestrator LLM to GENUINELY choose the next action from a
    ranked, evidence-annotated shortlist. The graph scores are advisory inputs,
    not a mandate: the model may pick a lower-scored option, or stop, when it
    can justify doing so from the evidence."""
    recon = state.get("recon_state", {})
    sqli = state.get("sqli_state", {})
    xss = state.get("xss_state", {})
    idor = state.get("idor_state", {})
    attack_surface = recon.get("attack_surface", {})

    summary = {
        "executed": state.get("modules_run", []),
        "findings": len(state.get("findings", [])),
        "authenticated_session": bool(
            state.get("authenticated_session")
            or sqli.get("authenticated_session")
            or idor.get("authenticated_session")
        ),
        "surface": {
            "injection": len(attack_surface.get("injection", [])),
            "client_side": len(attack_surface.get("client_side", [])),
            "authorization": len(attack_surface.get("authorization", [])),
            "auth_endpoints": len(recon.get("auth_endpoints", [])),
            "user_endpoints": len(recon.get("user_endpoints", [])),
        },
        "results": {
            "sqli_successful": len(sqli.get("successful_targets", [])),
            "xss_successful": len(xss.get("successful_targets", [])),
            "idor_successful": len(idor.get("successful_targets", [])),
        },
    }

    # Ranked options the model chooses among (score = graph priority, 0..1).
    options = [
        {"action": s["action"], "score": s["score"], "why": s.get("reason", "")}
        for s in shortlist
    ]

    return f"""You are the strategy orchestrator for an authorized local web
security assessment. Decide the single most valuable next action.

Assessment state:
{json.dumps(summary, separators=(",", ":"), default=str)}

Ranked candidate actions (graph priority score 0-1 is ADVISORY — you may choose
a different available action, or a lower-scored one, if the evidence justifies
it; choose "stop" only when no available action would add value):
{json.dumps(options, separators=(",", ":"), default=str)}

Available actions you may choose: {available + ["stop"]}

Strategy guidance:
- Prioritize actions that turn suspected findings into confirmed ones, or that
  exploit an already-obtained authenticated session (idor/authorization).
- Do not repeat completed modules. Never invent targets or expose tokens.

Return ONLY JSON: {{"action":"<one of the available actions>","reason":"<1-2 sentence justification referencing the evidence>"}}"""


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


ORCHESTRATOR_SYSTEM = (
    "You are the central orchestration AI for an authorized local web "
    "application security test. You coordinate specialist agents and decide "
    "the next action. Never invent targets or vulnerabilities, never expose "
    "authentication tokens. Return ONLY valid JSON."
)


def get_graph_shortlist(state, k=4):
    """Return the top-k valid next-action candidates from the attack graph,
    each with its score and evidence reason, for the orchestrator LLM to
    choose among. The graph ranks; the LLM decides."""
    graph = state.get("attack_graph")
    if not graph:
        return []
    graph.infer_relationships()
    candidates = graph.validate_hypotheses(state)  # sorted by score desc
    executed = state.get("modules_run", [])

    allowed = {m for m in CORE_MODULES if m not in executed}
    if "idor_check" not in executed:
        allowed.add("idor_check")

    shortlist, seen = [], set()
    for c in candidates:
        target = c.get("target")
        if (
            not target
            or target in seen
            or target not in allowed
            or (c.get("score") or 0) <= 0
        ):
            continue
        seen.add(target)
        shortlist.append({
            "action": target,
            "score": c.get("score", 0.0),
            "reason": c.get("reason", ""),
        })
        if len(shortlist) >= k:
            break
    return shortlist


def decide_next_module(state):
    executed = state.get("modules_run", [])

    # 1. Reconnaissance always runs first.
    if not executed:
        return {
            "action": "recon",
            "reason": "Reconnaissance is required before any testing.",
        }

    # Baseline (non-adaptive control): a traditional linear scanner. Runs the
    # core modules in a fixed order with NO attack graph, NO LLM reasoning, and
    # NO chaining — so it never reaches IDOR, modelling what adaptive chaining
    # overcomes. Used by the baseline-vs-adaptive evaluation.
    if not state.get("chaining_enabled", True):
        for mod in CORE_MODULES:
            if mod not in executed:
                return {
                    "action": mod,
                    "reason": "Baseline linear execution (adaptive chaining disabled).",
                }
        return {"action": "stop", "reason": "Baseline linear assessment complete."}

    # 2. A verified multi-step chain is a hard follow-up and is never skipped
    #    (reliability guarantee for evidence-backed exploit chains).
    pending_chain = state.get("pending_chain")
    if pending_chain and pending_chain.get("next_module"):
        nm = pending_chain.get("next_module")
        return {
            "action": nm,
            "reason": (
                f"Verified {pending_chain.get('chain', 'exploit')} chain: "
                f"executing the required follow-up '{nm}'."
            ),
        }

    available = [m for m in CORE_MODULES if m not in executed]
    if not available:
        return {"action": "stop", "reason": "All useful modules completed."}

    shortlist = get_graph_shortlist(state)
    allowed = set(available) | {"stop"}
    if "idor_check" not in executed:
        allowed.add("idor_check")

    # 3. The LLM GENUINELY chooses among the ranked, evidence-annotated options
    #    (scores are advisory). The graph informs; the model strategizes.
    prompt = build_decision_prompt(state, shortlist, available)
    decision = None
    try:
        response = llm.invoke([
            ("system", ORCHESTRATOR_SYSTEM),
            ("human", prompt),
        ])
        decision = parse_decision(response)
    except Exception as e:
        print(f"[ORCHESTRATOR] LLM decision failed: {e}")

    action = decision.get("action") if isinstance(decision, dict) else None

    # 4. Validate the model's choice; fall back to the graph's top action.
    if action in allowed:
        print(f"[ORCHESTRATOR] LLM selected: {action}")
        return decision

    if action is not None:
        print(
            f"[ORCHESTRATOR] LLM returned invalid action '{action}'; "
            "using the highest-priority graph action."
        )
    fallback = shortlist[0]["action"] if shortlist else available[0]
    return {
        "action": fallback,
        "reason": "Highest-priority valid action (orchestrator fallback).",
    }


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

        result = run_recon_specialist(
            state
        )
        update_attack_graph_from_recon(
            state,
            result
        )
        return result

    if action == "auth":

        recon_result = extract_recon_result(
            state
        )

        # Seed auth with emails discovered elsewhere (e.g. an exposed user
        # listing from the authorization module) so its user-enumeration probe
        # has real candidates to differentiate against.
        emails = _collect_discovered_emails(state)
        if emails and isinstance(recon_result, dict):
            recon_result = dict(recon_result)
            data = dict(recon_result.get("data") or {})
            data["discovered_emails"] = emails
            recon_result["data"] = data

        result = run_auth_specialist(
            recon_result
        )

        # Persist auth module state (used by the dashboard and the graph's
        # session check); drop any session material before storing.
        if isinstance(result, dict) and isinstance(result.get("state"), dict):
            auth_persist = dict(result["state"])
            auth_persist.pop("authenticated_session", None)
            state["auth_state"] = auth_persist

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

        if authenticated_session:
            state["idor_state"][
                "authenticated_session"
            ] = authenticated_session

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

        # Persist the module state so the dashboard's Authorization section can
        # read real metrics (targets tested, suspected BOLA, confirmed bypass).
        # The authenticated session is dropped — it must not leak into the UI.
        if isinstance(result, dict) and isinstance(result.get("state"), dict):
            authz_persist = dict(result["state"])
            authz_persist.pop("authenticated_session", None)
            state["authz_state"] = authz_persist

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

    graph = state.get("attack_graph")
    if graph and hasattr(graph, "add_node"):
        graph.add_node(
            f"module:{action}",
            action,
            {
                "completed": bool(
                    isinstance(result, dict)
                    and result.get("completed")
                ),
                "findings": len(
                    result.get("findings", [])
                )
                if isinstance(result, dict)
                else 0
            }
        )

    if not isinstance(result, dict):
        result = {
            "specialist": action,
            "completed": False,
            "error": "Invalid module result."
        }

    result_data = result.get("data")
    evidence_data = result_data if isinstance(result_data, dict) else result
    confirmed = evidence_data.get("confirmed") is True
    bypass_verified = (
        evidence_data.get("authentication_bypass_verified") is True
    )

    # A multi-step chain is triggered when the specialist flags it AND the
    # evidence is strong enough: either the vulnerability is confirmed, or a
    # SQLi-caused authentication bypass has been independently verified
    # (benign credentials fail while the injection payload authenticates).
    # An ordinary successful login or a lone session cookie is NOT enough and
    # never sets authentication_bypass_verified.
    chain_data_obj = (
        result.get("chain_data")
        if isinstance(result.get("chain_data"), dict)
        else None
    )

    if (
        result.get("chain_trigger") is True
        and chain_data_obj is not None
        and (confirmed or bypass_verified)
        and state.get("chaining_enabled", True)
    ):
        # pending_chain holds the authenticated session internally so the IDOR
        # step can use it; it is never printed/reported.
        state["pending_chain"] = chain_data_obj
        state["metrics"]["chains_triggered"] += 1

        # Record the trigger in chain_history (redacted: no session/token).
        state.setdefault("chain_history", []).append({
            "type": chain_data_obj.get("chain"),
            "source": action,
            "next_module": chain_data_obj.get("next_module"),
            "status": "triggered",
        })

    # Never let a raw session/token reach findings, logs, the dashboard, or
    # reports: the findings-facing copy of chain_data is redacted while
    # pending_chain (above) keeps the intact session for internal use only.
    if chain_data_obj is not None:
        result = dict(result)
        result["chain_data"] = _redact_chain_data(chain_data_obj)


    category_map = {
        "xss_check": "xss",
        "sqli_check": "sqli",
        "idor_check": "idor",
        "authorization": "auth",
        "auth": "auth",
        "recon": "recon"
    }

    canonical_category = category_map.get(
        action,
        action
    )

    findings_to_add = []

    module_finding = {
        "finding_type": canonical_category,
        "category": canonical_category,
        "vulnerable": False,
        "data": result
    }

    if result.get("vulnerable") is True:
        module_finding["vulnerable"] = True

    data = result.get("data")

    if isinstance(data, dict):

        if data.get("vulnerable") is True:
            module_finding["vulnerable"] = True

        if isinstance(
            data.get("findings"),
            list
        ):
            module_finding["findings"] = data[
                "findings"
            ]

    findings_to_add.append(
        module_finding
    )

    successful_targets = result.get(
        "findings"
    )

    if not isinstance(
        successful_targets,
        list
    ):
        successful_targets = []

    if not successful_targets and isinstance(
        data,
        dict
    ):
        successful_targets = data.get(
            "successful_targets",
            []
        )

    for target in successful_targets:

        if not isinstance(
            target,
            dict
        ):
            continue

        finding = dict(target)

        finding["finding_type"] = (
            category_map.get(
                finding.get("finding_type"),
                finding.get("finding_type")
            )
            or canonical_category
        )

        finding["category"] = (
            category_map.get(
                finding.get("category"),
                finding.get("category")
            )
            or canonical_category
        )

        if "vulnerable" not in finding:
            finding["vulnerable"] = True

        findings_to_add.append(
            finding
        )

    for finding in findings_to_add:

        finding = sanitize_session_from_result(
            finding
        )

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

    if graph and hasattr(graph, "infer_relationships"):
        graph.infer_relationships()


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


def get_graph_next_action(state):
    graph = state.get("attack_graph")
    
    if not graph:
        return None
        
    chains = graph.generate_chains(state)
    
    if not chains:
        return None
        
    ranked = graph.rank_chains(
        chains,
        state
    )
    
    if not ranked:
        return None
        
    best = ranked[0]
    chain = best["chain"]
    score = best["score"]
    
    state["selected_chain"] = chain
    # Graph hypotheses are transparency/debug data, NOT triggered chains.
    # Keeping them out of chain_history ensures chain counters and history
    # reflect only chains that actually fired.
    state.setdefault("graph_selections", []).append({
        "chain": chain,
        "score": score
    })

    if not chain:
        return None
        
    for action in chain:
        if action not in state.get("modules_run", []):
            print(
                f"[ATTACK GRAPH] Selected chain: {chain}"
            )
            print(
                f"[ATTACK GRAPH] Chain score: {score}"
            )
            print(
                f"[ATTACK GRAPH] Next action: {action}"
            )
            return action
            
    return None


def _assessment_digest(state):
    """Compact, redacted evidence digest for the executive-summary LLM call.
    Counts and endpoints only — never raw data, sessions, or tokens."""
    sqli = state.get("sqli_state", {}) or {}
    xss = state.get("xss_state", {}) or {}
    idor = state.get("idor_state", {}) or {}
    authz = state.get("authz_state", {}) or {}
    auth = state.get("auth_state", {}) or {}
    metrics = state.get("metrics", {}) or {}

    def _endpoints(items, n=3):
        out = []
        for it in (items or [])[:n]:
            if isinstance(it, dict):
                tgt = it.get("target") if isinstance(it.get("target"), dict) else it
                url = (
                    (tgt or {}).get("url")
                    or it.get("endpoint")
                    or it.get("url")
                )
                if url:
                    out.append(str(url))
        return out

    return {
        "target": state.get("target_url"),
        "modules_run": state.get("modules_run", []),
        "chains_triggered": metrics.get("chains_triggered", 0),
        "chains_completed": metrics.get("chains_completed", 0),
        "sqli": {
            "confirmed": len(sqli.get("confirmed_vulnerabilities", [])),
            "auth_bypass_suspected": len(sqli.get("successful_targets", [])),
        },
        "idor": {
            "unauthorized_access": len(idor.get("successful_targets", [])),
            "endpoints": _endpoints(idor.get("successful_targets", [])),
        },
        "xss": {
            "confirmed": len(xss.get("confirmed_vulnerabilities", [])),
            "potential": len(xss.get("potential_findings", [])),
            "suspected": len(xss.get("successful_targets", [])),
        },
        "authorization": {
            "suspected": len(authz.get("successful_targets", [])),
            "confirmed": len(authz.get("confirmed_vulnerabilities", [])),
        },
        "auth": {"findings": len(auth.get("findings", []))},
    }


def _fallback_summary(digest):
    """Deterministic summary used when the LLM is unavailable."""
    parts = [
        f"Authorized assessment of {digest.get('target')} executed "
        f"{len(digest.get('modules_run', []))} testing modules."
    ]
    if digest["sqli"]["confirmed"] or digest["sqli"]["auth_bypass_suspected"]:
        parts.append(
            "A SQL-injection authentication bypass was observed on the login flow."
        )
    if digest["idor"]["unauthorized_access"]:
        parts.append(
            f"IDOR testing confirmed {digest['idor']['unauthorized_access']} "
            "unauthorized cross-user resource access(es)."
        )
    if digest["chains_completed"]:
        parts.append(
            "A multi-step attack chain (SQLi to IDOR) was triggered and completed."
        )
    if digest["xss"]["confirmed"] or digest["xss"]["potential"]:
        parts.append(
            f"XSS testing produced {digest['xss']['confirmed']} confirmed and "
            f"{digest['xss']['potential']} potential findings."
        )
    if digest["authorization"]["suspected"] or digest["auth"]["findings"]:
        parts.append(
            "Authorization/authentication analysis flagged suspected access-control weaknesses."
        )
    parts.append(
        "Prioritized remediation: parameterize database queries, enforce "
        "object-level authorization checks, and apply contextual output encoding."
    )
    return " ".join(parts)


def _unwrap_summary_text(text):
    """The model sometimes returns the summary wrapped in JSON like
    {"summary":"..."}. Extract the prose when that happens."""
    if not text:
        return ""
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                for key in ("summary", "executive_summary", "text", "narrative"):
                    val = obj.get(key)
                    if isinstance(val, str) and val.strip():
                        return val.strip()
                # fall back to the first string value
                for val in obj.values():
                    if isinstance(val, str) and val.strip():
                        return val.strip()
        except Exception:
            pass
    return stripped


def generate_executive_summary(state):
    """AI-authored executive summary of the assessment (the model reasoning
    about the findings). Falls back to a deterministic summary if the LLM is
    unavailable. Never includes raw data, sessions, or tokens."""
    digest = _assessment_digest(state)
    prompt = (
        "Write a concise, professional penetration-test executive summary "
        "(120-180 words) for an AUTHORIZED assessment. Use ONLY the evidence "
        "digest below; do not invent findings or expose any tokens. Cover: "
        "overall risk posture, the most significant confirmed findings, the "
        "multi-step attack chain if one occurred, and 2-3 prioritized "
        "recommendations. Output PLAIN PROSE TEXT ONLY — not JSON, no keys, no "
        "markdown headers.\n\n"
        f"Evidence digest: {json.dumps(digest, separators=(',', ':'), default=str)}"
    )
    try:
        response = llm.invoke([
            ("system", ORCHESTRATOR_SYSTEM),
            ("human", prompt),
        ])
        text = str(getattr(response, "content", "") or "").strip()
        text = _unwrap_summary_text(text)
        if not text:
            text = _fallback_summary(digest)
    except Exception as e:
        print(f"[ORCHESTRATOR] Executive summary generation failed: {e}")
        text = _fallback_summary(digest)

    state["executive_summary"] = text
    return text


def run_agent(
    target_url="http://localhost:3000",
    chaining_enabled=True
):

    state = initial_state(
        target_url=target_url,
        chaining_enabled=chaining_enabled
    )
    state["attack_graph"] = AttackGraph()

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

    raw_risks = analyze_all(state["findings"])
    unique_risks = []
    seen_categories = set()
    for risk in raw_risks:
        category = risk.get("category")
        if category in seen_categories:
            continue
        seen_categories.add(category)
        unique_risks.append(risk)
    state["risk_assessments"] = unique_risks

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

    # AI-authored executive summary (the model reasoning about the results).
    summary = generate_executive_summary(state)
    print("\n" + "=" * 70)
    print("EXECUTIVE SUMMARY (AI-generated)")
    print("=" * 70)
    safe_print(summary)

    return state


if __name__ == "__main__":
    run_agent()