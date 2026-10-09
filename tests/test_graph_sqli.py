from modules.attack_graph import AttackGraph
import pprint

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

candidates = graph.validate_hypotheses(state)

print("\n=== GRAPH SQLi TEST ===")
for candidate in candidates:
    pprint.pprint(candidate)

sqli = next(
    c for c in candidates
    if c["target"] == "sqli_check"
)

print("\nPASS: Attack Graph dynamically generated SQLi action.")
