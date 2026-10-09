import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state import initial_state
from tools.xss_tools import execute_xss_test

state = initial_state("http://localhost:3000")

target = {
    "url": "http://localhost:3000/#/search?q=apple",
    "xss_target_type": "fragment",
    "parameter": "q"
}

print("Testing URL Parameter XSS on:", target["url"])
result = execute_xss_test(state, target)
print("Result:")
print(result)
