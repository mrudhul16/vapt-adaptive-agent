from modules.attack_graph import AttackGraph

graph = AttackGraph()

graph.add_node(
    "injection:0",
    "injection",
    {"url": "/rest/products/search"}
)

graph.add_node(
    "user:0",
    "user",
    {"url": "/api/Basket"}
)

graph.infer_relationships()

state = {
    "findings": [
        {
            "category": "sqli",
            "vulnerable": True
        }
    ],
    "authenticated_session": "internal-test-session",
    "sqli_state": {
        "authenticated_session": "internal-test-session"
    },
    "idor_state": {}
}

candidates = graph.validate_hypotheses(state)

print("\n=== DYNAMIC CHAIN TEST ===")
for c in candidates:
    import pprint
    pprint.pprint(c)
