import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from groq import RateLimitError

load_dotenv()

AGENT_KEY_PAIRS = {
    "recon": (1, 2),
    "auth": (3, 4),
    "sqli": (5, 6),
    "idor": (7, 8),
    "xss": (9, 10),
    "authorization": (11, 12),
    "orchestrator": (13, 14),
}

def _get_keys(agent_name):
    agent_name = agent_name.lower()
    if agent_name not in AGENT_KEY_PAIRS:
        raise ValueError(f"Unknown agent: {agent_name}")
    primary, fallback = AGENT_KEY_PAIRS[agent_name]
    primary_key = os.getenv(f"GROQ_API_KEY_{primary}")
    fallback_key = os.getenv(f"GROQ_API_KEY_{fallback}")
    if not primary_key:
        raise RuntimeError(f"Missing GROQ_API_KEY_{primary}")
    if not fallback_key:
        raise RuntimeError(f"Missing GROQ_API_KEY_{fallback}")
    return primary_key, fallback_key

class FallbackLLM:
    def __init__(self, agent_name, primary_llm, fallback_llm):
        self.agent_name = agent_name
        self.primary_llm = primary_llm
        self.fallback_llm = fallback_llm

    def invoke(self, *args, **kwargs):
        try:
            return self.primary_llm.invoke(*args, **kwargs)
        except RateLimitError:
            print(
                f"[{self.agent_name.upper()}] Primary key rate limited. "
                f"Switching to fallback key..."
            )
            return self.fallback_llm.invoke(*args, **kwargs)

def get_llm(agent_name):
    primary_key, fallback_key = _get_keys(agent_name)
    
    primary_llm = ChatGroq(
        model="openai/gpt-oss-120b",
        temperature=0,
        api_key=primary_key,
    )
    
    fallback_llm = ChatGroq(
        model="openai/gpt-oss-120b",
        temperature=0,
        api_key=fallback_key,
    )
    
    return FallbackLLM(agent_name, primary_llm, fallback_llm)
