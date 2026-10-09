import sys
import os
import pprint
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state import initial_state
from tools.xss_tools import execute_xss_test

state = initial_state("http://localhost:3000")

# Simulate a stored XSS target passed from the agent
target = {
    "url": "http://localhost:3000/rest/products/1/reviews",
    "xss_target_type": "stored",
    "type": "stored"
}

print("Running Stored XSS Workflow on:", target["url"])
result = execute_xss_test(state, target)

# Print the sanitized result output without tokens or raw requests
print("\n[RESULT]")
pprint.pprint(result, width=120)

# Verify cleanup worked by checking the reviews list
import requests
print("\n[CLEANUP VERIFICATION]")
get_r = requests.get("http://localhost:3000/rest/products/1/reviews", timeout=5)
reviews = get_r.json().get("data", [])
cleaned_reviews = [r for r in reviews if r.get("message") == "CLEANED_UP_VAPT_TEST"]
print(f"Found {len(cleaned_reviews)} cleaned up test reviews!")
