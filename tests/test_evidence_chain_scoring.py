from modules.attack_graph import AttackGraph

graph = AttackGraph()

state = {
    "modules_run": ["recon"],
    "findings": [],
    "authenticated_session": None,
    "sqli_state": {}
}

chains = [
    ["sqli_check", "idor_check"],
    ["xss_check"]
]

ranked = graph.rank_chains(chains, state)

print("\n=== BEFORE EVIDENCE ===")

for item in ranked:
    print(
        f"Chain: {item['chain']} "
        f"Score: {item['score']}"
    )

before_best = ranked[0]["chain"]

state["findings"].append({
    "category": "sqli",
    "vulnerable": True
})

state["authenticated_session"] = "internal-test-session"

state["sqli_state"] = {
    "authenticated_session": "internal-test-session"
}

ranked = graph.rank_chains(chains, state)

print("\n=== AFTER SQLi + SESSION EVIDENCE ===")

for item in ranked:
    print(
        f"Chain: {item['chain']} "
        f"Score: {item['score']}"
    )

after_best = ranked[0]["chain"]

assert after_best == [
    "sqli_check",
    "idor_check"
]

assert ranked[0]["score"] == 1.0

print("\nBefore evidence:", before_best)
print("After evidence:", after_best)

print(
    "\nPASS: Chain ranking changed "
    "based on application evidence."
)
