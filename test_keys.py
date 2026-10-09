from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()

for n in [13, 14]:
    key = os.getenv(f"GROQ_API_KEY_{n}")
    print(f"\nTesting KEY {n}")
    try:
        client = Groq(api_key=key)
        client.models.list()
        print(f"KEY {n}: VALID")
    except Exception as e:
        print(f"KEY {n}: FAILED")
        print(type(e).__name__)
        print(str(e)[:300])
