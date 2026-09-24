import os
from dotenv import load_dotenv
load_dotenv()

from langchain_groq import ChatGroq

llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0)
try:
    print(llm.invoke("Hi"))
except Exception as e:
    print(repr(e))
