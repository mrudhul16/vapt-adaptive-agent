import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from agents.auth_runner import run_auth_specialist


recon_state = {
    "attack_surface": {
        "authentication": [
            {
                "type": "endpoint",
                "url": "http://localhost:3000/login",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/register",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/login",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/reset-password",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/change-password?current=",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/whoami",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/security-question?email=",
                "method": "GET"
            },
            {
                "type": "endpoint",
                "url": "http://localhost:3000/rest/user/authentication-details/",
                "method": "GET"
            }
        ]
    },
    "auth_endpoints": [
        "http://localhost:3000/login",
        "http://localhost:3000/register",
        "http://localhost:3000/rest/user/login",
        "http://localhost:3000/rest/user/reset-password",
        "http://localhost:3000/rest/user/change-password?current=",
        "http://localhost:3000/rest/user/whoami",
        "http://localhost:3000/rest/user/security-question?email=",
        "http://localhost:3000/rest/user/authentication-details/"
    ]
}


print()
print("=" * 60)
print("AUTH AGENT STANDALONE TEST")
print("=" * 60)

result = run_auth_specialist(recon_state)

print()
print("=" * 60)
print("FINAL AUTH RESULT")
print("=" * 60)

print(result)