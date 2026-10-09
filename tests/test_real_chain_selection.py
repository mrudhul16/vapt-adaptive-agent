from modules.attack_graph import AttackGraph
from agent import get_graph_next_action

graph = AttackGraph()

graph.add_node(
    "injection:0",
    "injection",
    {"url": "/search"}
)

graph.add_node(
    "user:0",
    "user",
    {"url": "/api/Basket"}
)

graph.infer_relationships()

state = {
    "attack_graph": graph,
    "modules_run": ["recon"],
    "findings": [],
    "authenticated_session": None,
    "sqli_state": {}
}

print("\n=== MULTI-STEP CHAIN SELECTION TEST ===")

action = get_graph_next_action(state)

print("\nFirst selected action:", action)
assert action == "sqli_check"
assert state["selected_chain"] == [
    "sqli_check",
    "idor_check"
]

# Simulate execution of SQLi
state["modules_run"].append("sqli_check")
state["findings"].append({
    "category": "sqli",
    "vulnerable": True
})
state["authenticated_session"] = "test-session"
state["sqli_state"] = {"authenticated_session": "test-session"}
state["idor_state"] = {}

action = get_graph_next_action(state)

print("\nNext selected action:", action)
assert action == "idor_check"
assert state["selected_chain"] == [
    "idor_check"
]
# Graph hypotheses are tracked in graph_selections (not chain_history, which
# is reserved for chains that actually triggered).
assert len(state["graph_selections"]) == 2

print("\nPASS: Attack Graph dynamically executed a multi-step attack chain.")
print("PASS: Selected chain and chain history persisted in shared state.")
