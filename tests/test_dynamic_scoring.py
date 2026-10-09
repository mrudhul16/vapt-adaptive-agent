from modules.attack_graph import AttackGraph
import pprint

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
    "modules_run": ["recon"],
    "findings": [],
    "authenticated_session": None,
    "sqli_state": {}
}

candidates = graph.validate_hypotheses(state)

print("\n=== DYNAMIC SCORING TEST ===")

for candidate in candidates:
    pprint.pprint(candidate)

sqli = next(
    c for c in candidates
    if c["target"] == "sqli_check"
)

# Base 0.60 + 0.30 because an injection node is present.
assert sqli["score"] == 0.90

state["findings"].append({
    "category": "sqli",
    "vulnerable": True
})

state["authenticated_session"] = "internal-test-session"
state["sqli_state"] = {
    "authenticated_session": "internal-test-session"
}

candidates = graph.validate_hypotheses(state)

idor = next(
    c for c in candidates
    if c["target"] == "idor_check"
)

print("\nAfter SQLi evidence:")
pprint.pprint(idor)

# Session + user resource + confirmed SQLi pushes IDOR to the maximum.
assert idor["score"] == 1.0

print("\nPASS: Attack Graph dynamically recalculated action priority.")
