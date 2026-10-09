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
    "modules_run": ["recon", "sqli_check"],
    "findings": [
        {
            "category": "sqli",
            "vulnerable": True
        }
    ],
    "authenticated_session": "internal-test-session",
    "sqli_state": {
        "authenticated_session": "internal-test-session"
    }
}

action = get_graph_next_action(state)

print("\n=== HIGHEST SCORE SELECTION TEST ===")
print("Selected action:", action)

assert action == "idor_check"

print(
    "PASS: Attack Graph selected the "
    "highest-scoring available action."
)
