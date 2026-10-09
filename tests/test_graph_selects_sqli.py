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

next_action = get_graph_next_action(state)

print("\n=== GRAPH SQLi SELECTION TEST ===")
print("Next action:", next_action)
assert next_action == "sqli_check"
print("PASS: Attack Graph selected SQLi dynamically.")
