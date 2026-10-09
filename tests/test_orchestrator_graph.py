from agent import decide_next_module
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

state = {
    "attack_graph": graph,
    "modules_run": [
        "recon",
        "auth",
        "sqli_check"
    ],
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

print("\n=== ORCHESTRATOR GRAPH INTEGRATION TEST ===")
decision = decide_next_module(state)
print("Decision:", decision)

assert decision["action"] == "idor_check"
print("PASS: Orchestrator selected IDOR through the Attack Graph.")
