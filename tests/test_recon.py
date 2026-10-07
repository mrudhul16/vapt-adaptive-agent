import sys
from pathlib import Path

sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parent.parent
    )
)

from state import initial_state
from agents.recon_runner import run_recon_specialist


state = initial_state(
    "http://localhost:3000"
)

state["recon_state"] = {
    "discovered_targets": [],
    "tested_targets": [],
    "successful_targets": [],
    "interesting_targets": [],
    "remaining_targets": [],
    "observations": [],
    "technologies": [],
    "endpoints": [],
    "forms": [],
    "parameters": [],
    "current_target": None,
    "iteration": 0,
    "completed": False
}


result = run_recon_specialist(
    state
)

print()
print("=" * 60)
print("FINAL RECON RESULT")
print("=" * 60)

print(result)

print()
print("=" * 60)
print("FINAL RECON STATE")
print("=" * 60)

print(state["recon_state"])