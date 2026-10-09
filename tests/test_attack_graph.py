from modules.attack_graph import AttackGraph

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

print("\n=== ATTACK GRAPH TEST ===")
print("Nodes:")
for node in graph.nodes.values():
    print(node)

print("\nHypotheses:")
for hypothesis in graph.get_candidates():
    print(hypothesis)
