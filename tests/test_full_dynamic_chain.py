from agent import get_graph_next_action
from modules.attack_graph import AttackGraph

graph = AttackGraph()
graph.add_node(
    "injection:0",
    "injection",
    {"url": "/rest/products/search?q="}
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
    "findings": []
}

print("\n=== FULL DYNAMIC CHAIN TEST ===")

# Step 1: Recon -> SQLi
next_action = get_graph_next_action(state)
print("Step 1:", next_action)
assert next_action == "sqli_check"

# Simulate SQLi execution
state["modules_run"].append("sqli_check")
state["findings"].append({
    "category": "sqli",
    "vulnerable": True
})
state["authenticated_session"] = "internal-test-session"
state["sqli_state"] = {
    "authenticated_session": "internal-test-session"
}
state["idor_state"] = {}

# Step 2: SQLi -> IDOR
next_action = get_graph_next_action(state)
print("Step 2:", next_action)
assert next_action == "idor_check"

print("\nPASS: Full SQLi -> authenticated session -> IDOR chain discovered dynamically.")
