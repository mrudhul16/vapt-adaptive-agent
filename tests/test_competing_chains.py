from modules.attack_graph import AttackGraph

graph = AttackGraph()

state = {
    # SQLi evidence is present (a session was produced), but the sqli_check
    # module is still the entry point of the chain being evaluated, so it is
    # not yet in modules_run.
    "modules_run": ["recon"],
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

chains = [
    ["sqli_check", "idor_check"],
    ["xss_check"],
    ["authorization"]
]

ranked = graph.rank_chains(chains, state)

print("\n=== COMPETING CHAINS TEST ===")

for item in ranked:
    print(
        f"Chain: {item['chain']} "
        f"Score: {item['score']}"
    )

assert ranked[0]["chain"] == [
    "sqli_check",
    "idor_check"
]

print(
    "\nPASS: Attack Graph selected "
    "the highest-value attack chain."
)
