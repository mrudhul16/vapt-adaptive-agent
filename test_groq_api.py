import os
from dotenv import load_dotenv
from groq_key_manager import get_llm

load_dotenv()

llm = get_llm("orchestrator")

prompt = "Hello! Please summarize the history of the internet in 500 words. " * 50

for i in range(10):
    print(f"\n--- Request {i+1} ---")
    try:
        res = llm.invoke(prompt)
        print("Success! length:", len(res.content))
    except Exception as e:
        print(f"FAILED: {e}")
        break
