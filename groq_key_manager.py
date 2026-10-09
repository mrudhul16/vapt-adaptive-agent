import os
from dotenv import load_dotenv

# Make Python's TLS use the operating system's trust store (the same CAs that
# curl and the system use). Without this, environments with a corporate/AV
# root CA fail every Groq SDK call with
#   SSL: CERTIFICATE_VERIFY_FAILED - unable to get local issuer certificate
# because the Groq SDK's httpx client only trusts the bundled certifi CAs,
# surfacing as a generic APIConnectionError ("Connection error."). This must
# run before any HTTPS client is created.
try:
    import truststore
    truststore.inject_into_ssl()
except Exception:
    pass

from langchain_groq import ChatGroq

load_dotenv()

MODEL = "openai/gpt-oss-120b"

# Token optimization: gpt-oss is a reasoning model whose hidden reasoning
# tokens dominate cost. "low" reasoning effort roughly halves completion
# tokens while still returning valid JSON for these structured decisions.
REASONING_EFFORT = "low"

# Per-agent completion ceiling (safety against runaway output). Decisions are
# compact JSON, so modest caps are plenty; generous enough not to truncate.
AGENT_MAX_TOKENS = {
    "recon": 500,
    "auth": 300,
    "sqli": 300,
    "idor": 900,
    "xss": 400,
    "authorization": 300,
    "orchestrator": 500,
}

# One Groq API key per agent (GROQ_API_KEY_<n> in the environment). These are
# the original primary keys; the secondary/fallback keys have been removed.
AGENT_KEYS = {
    "recon": 1,
    "auth": 3,
    "sqli": 5,
    "idor": 7,
    "xss": 9,
    "authorization": 11,
    "orchestrator": 13,
}


def _get_key(agent_name):
    agent_name = agent_name.lower()
    if agent_name not in AGENT_KEYS:
        raise ValueError(f"Unknown agent: {agent_name}")
    index = AGENT_KEYS[agent_name]
    key = os.getenv(f"GROQ_API_KEY_{index}")
    if not key:
        raise RuntimeError(f"Missing GROQ_API_KEY_{index}")
    return key


def get_llm(agent_name):
    """Return a Groq chat model for the given agent, using its single API key.

    Token usage is minimized via low reasoning effort and a per-agent
    completion ceiling.
    """
    return ChatGroq(
        model=MODEL,
        temperature=0,
        api_key=_get_key(agent_name),
        reasoning_effort=REASONING_EFFORT,
        max_tokens=AGENT_MAX_TOKENS.get(agent_name.lower(), 500),
    )
