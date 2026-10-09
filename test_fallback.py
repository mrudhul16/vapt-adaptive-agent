from groq_key_manager import get_llm
from groq import RateLimitError
import httpx

print("Initializing orchestrator LLM (Keys 13 & 14)...")
llm = get_llm("orchestrator")

# Mock the primary LLM to ALWAYS raise a RateLimitError
def mock_rate_limit(*args, **kwargs):
    raise RateLimitError(
        message="Simulated rate limit error",
        response=httpx.Response(status_code=429, request=httpx.Request("POST", "https://api.groq.com/v1/chat/completions")),
        body=None
    )

class MockPrimaryLLM:
    def invoke(self, *args, **kwargs):
        return mock_rate_limit(*args, **kwargs)

llm.primary_llm = MockPrimaryLLM()

print("\nInvoking LLM...")
try:
    response = llm.invoke("Hello, are you there?")
    print("\nRESPONSE RECEIVED:")
    print(response.content)
except Exception as e:
    print(f"\nSCRIPT FAILED: {e}")
