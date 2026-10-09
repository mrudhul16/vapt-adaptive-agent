import io
import sys
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

print("\n=== FINAL ADAPTIVE CHAIN TEST ===\n")

# Capture internal prints from agent.py to keep output clean
old_stdout = sys.stdout
sys.stdout = io.StringIO()

action1 = get_graph_next_action(state)
initial_chain = list(state.get("selected_chain", []))

sys.stdout = old_stdout

print("Initial chain:")
print(initial_chain)
print("\nAction 1:")
print(action1)
print("\nEvidence:")
print("SQLi confirmed")
print("Authenticated session obtained")

# Simulate evidence
state["modules_run"].append(action1)
state["findings"].append({
    "category": "sqli",
    "vulnerable": True
})
state["authenticated_session"] = "internal-test-session"
state["sqli_state"] = {"authenticated_session": "internal-test-session"}

# Capture internal prints from agent.py again
sys.stdout = io.StringIO()

action2 = get_graph_next_action(state)
recalculated_chain = list(state.get("selected_chain", []))

sys.stdout = old_stdout

print("\nRecalculated chain:")
print(recalculated_chain)
print("\nAction 2:")
print(action2)

print("\nChain history:")
for idx, entry in enumerate(state.get("chain_history", [])):
    print(f"{idx + 1}. {entry['chain']}")

assert action1 == "sqli_check"
assert action2 == "idor_check"
assert initial_chain == ["sqli_check", "idor_check"]
assert recalculated_chain == ["idor_check"]

print("\nPASS: Adaptive attack chain discovered and")
print("executed dynamically from application state.")
