"""Regression tests locking in the optimized attack-graph guidance."""

from modules.attack_graph import AttackGraph


def _graph_with_full_surface():
    g = AttackGraph()
    g.add_node("injection:0", "injection", {"url": "/rest/products/search"})
    g.add_node("client_side:0", "client_side", {"url": "/#/search"})
    g.add_node("authentication:0", "authentication", {"url": "/rest/user/login"})
    g.add_node("user_data:0", "user_data", {"url": "/rest/basket/1"})
    g.add_node("transactions:0", "transactions", {"url": "/rest/orders"})
    g.add_node("authorization:0", "authorization", {"url": "/api/Users"})
    g.infer_relationships()
    return g


def _top_action(graph, state):
    ranked = graph.rank_chains(graph.generate_chains(state), state)
    assert ranked, "expected at least one ranked chain"
    return ranked[0]["chain"][0], ranked[0]["score"]


def test_type_matching_generates_all_module_hypotheses():
    """The attack_surface category names must map to hypotheses (the old code
    only matched 'user'/'transaction' and silently dropped most)."""
    g = _graph_with_full_surface()
    targets = {h["target"] for h in g.hypotheses}
    assert {"sqli_check", "xss_check", "auth", "idor_check", "authorization"} <= targets


def test_fresh_scan_prioritizes_sqli_then_discovery():
    g = _graph_with_full_surface()
    state = {"modules_run": [], "findings": [], "sqli_state": {}, "idor_state": {}}
    action, score = _top_action(g, state)
    assert action == "sqli_check"
    assert score >= 0.85


def test_idor_suppressed_without_session():
    """Bare IDOR must not be selectable before any session exists."""
    g = _graph_with_full_surface()
    state = {"modules_run": [], "findings": [], "sqli_state": {}, "idor_state": {}}
    scored = {
        tuple(r["chain"]): r["score"]
        for r in g.rank_chains(g.generate_chains(state), state)
    }
    # the standalone idor chain either is absent or scores 0
    assert scored.get(("idor_check",), 0.0) == 0.0


def test_session_raises_idor_and_authorization():
    g = _graph_with_full_surface()
    state = {
        "modules_run": ["recon", "sqli_check"],
        "findings": [{"category": "sqli", "vulnerable": True}],
        "sqli_state": {"authenticated_session": {"token": "x"}},
        "idor_state": {},
    }
    scored = {
        r["chain"][0]: r["score"]
        for r in g.rank_chains(g.generate_chains(state), state)
    }
    assert scored.get("idor_check", 0) >= 0.85
    assert scored.get("authorization", 0) >= 0.85
    # auth drops once a session already exists
    assert scored.get("auth", 1.0) < scored.get("authorization", 0)


def test_auth_leads_when_no_session_and_no_sqli():
    """With no SQLi finding and no session, auth (to obtain one) should lead
    over the session-dependent follow-ups."""
    g = _graph_with_full_surface()
    state = {
        "modules_run": ["recon", "sqli_check"],
        "findings": [],
        "sqli_state": {},
        "idor_state": {},
    }
    action, score = _top_action(g, state)
    assert action in {"auth", "xss_check"}
    # auth must outrank authorization/idor when no session exists
    scored = {
        r["chain"][0]: r["score"]
        for r in g.rank_chains(g.generate_chains(state), state)
    }
    assert scored.get("auth", 0) >= scored.get("authorization", 0)


def test_executed_modules_are_not_reselected():
    g = _graph_with_full_surface()
    state = {
        "modules_run": ["recon", "sqli_check", "idor_check", "xss_check",
                        "authorization", "auth"],
        "findings": [{"category": "sqli", "vulnerable": True}],
        "sqli_state": {"authenticated_session": {"token": "x"}},
        "idor_state": {},
    }
    chains = g.generate_chains(state)
    # every module ran -> no chain should be produced
    assert chains == []
