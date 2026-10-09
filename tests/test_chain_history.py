"""chain_history / counters must reflect only chains that actually fired,
not every attack-graph hypothesis the orchestrator considered."""

from agent import update_state_after_module, get_graph_next_action
from modules.attack_graph import AttackGraph
from state import initial_state


def _state_with_graph():
    state = initial_state("http://localhost:3000")
    graph = AttackGraph()
    graph.add_node("injection:0", "injection", {"url": "/x"})
    graph.add_node("user_data:0", "user_data", {"url": "/rest/basket/1"})
    graph.infer_relationships()
    state["attack_graph"] = graph
    return state


def test_graph_selection_does_not_pollute_chain_history():
    state = _state_with_graph()
    get_graph_next_action(state)
    get_graph_next_action(state)
    # Graph hypotheses go to graph_selections, never chain_history.
    assert state.get("chain_history", []) == []
    assert len(state.get("graph_selections", [])) == 2


def test_triggered_chain_recorded_in_history():
    state = initial_state("http://localhost:3000")
    result = {
        "chain_trigger": True,
        "chain_data": {"chain": "sqli_to_idor", "next_module": "idor_check"},
        "data": {"confirmed": True, "vulnerable": True},
    }
    update_state_after_module(state, "sqli_check", result, "confirmed SQLi")

    assert state["metrics"]["chains_triggered"] == 1
    history = state.get("chain_history", [])
    assert len(history) == 1
    assert history[0]["type"] == "sqli_to_idor"
    assert history[0]["status"] == "triggered"
    assert history[0]["next_module"] == "idor_check"


def test_no_chain_no_history():
    state = initial_state("http://localhost:3000")
    result = {
        "chain_trigger": True,
        "chain_data": {"chain": "sqli_to_idor", "next_module": "idor_check"},
        "data": {"confirmed": False, "authentication_bypass_verified": False,
                 "authenticated": True},
    }
    update_state_after_module(state, "sqli_check", result, "ordinary login")
    assert state["metrics"]["chains_triggered"] == 0
    assert state.get("chain_history", []) == []
