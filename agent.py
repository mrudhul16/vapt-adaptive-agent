from langgraph.graph import StateGraph, END
from typing import TypedDict, List
from langchain_ollama import ChatOllama

llm = ChatOllama(model="llama3.1:8b")

# All modules the agent knows about, run once each unless chained back in
CORE_MODULES = ["fingerprint", "auth_check", "sqli_check", "xss_check"]
MAX_STEPS = 15  # safety net so a bug can't loop forever

class AgentState(TypedDict):
    findings: List[dict]
    modules_run: List[str]
    pending_chains: List[dict]
    _next_action: str
    decision_log: List[str]
    done: bool

# --- Stub modules (fake data — Person B will replace these with real logic) ---
def run_fingerprint():
    return {
        "finding_type": "tech_stack_identified",
        "data": {"stack": "Node.js + Express"},
        "chain_trigger": False,
        "chain_data": None
    }

def run_auth_check():
    return {
        "finding_type": "auth_token_found",
        "data": {"token": "abc123", "user": "lowpriv_user"},
        "chain_trigger": True,
        "chain_data": {"suggested_module": "idor_check", "token": "abc123"}
    }

def run_idor_check(token):
    print(f"  -> running IDOR check using token: {token}")
    return {
        "finding_type": "idor_confirmed",
        "data": {"leaked_user": "other_user"},
        "chain_trigger": False,
        "chain_data": None
    }

def run_sqli_check():
    return {
        "finding_type": "sqli_not_found",
        "data": {},
        "chain_trigger": False,
        "chain_data": None
    }

def run_xss_check():
    return {
        "finding_type": "xss_found",
        "data": {"field": "search_box"},
        "chain_trigger": False,
        "chain_data": None
    }

MODULE_RUNNERS = {
    "fingerprint": lambda state: run_fingerprint(),
    "auth_check": lambda state: run_auth_check(),
    "sqli_check": lambda state: run_sqli_check(),
    "xss_check": lambda state: run_xss_check(),
    "idor_check": lambda state: run_idor_check(state["pending_chains"][0]["token"]),
}

# --- decide_node: outputs #1, #2, #3, #4 ---
def decide_node(state: AgentState):
    step_num = len(state["decision_log"]) + 1

    # Safety cap
    if step_num > MAX_STEPS:
        reason = "hit max step limit — stopping to avoid infinite loop"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = "stop"
        state["done"] = True
        print(f"  [Step {step_num}] {reason}")
        return state

    # --- Output #3: chain-trigger OVERRIDES normal reasoning ---
    if state["pending_chains"]:
        chain = state["pending_chains"][0]  # oldest pending chain, FIFO
        action = chain["suggested_module"]
        reason = f"CHAINED into '{action}' because: previous finding provided data ({chain})"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = action
        print(f"  [Step {step_num}] {reason}")
        return state

    # --- Normal reasoning: any core modules left to run? ---
    remaining = [m for m in CORE_MODULES if m not in state["modules_run"]]

    if not remaining:
        reason = "all core modules run, no pending chains — assessment complete"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = "stop"
        state["done"] = True
        print(f"  [Step {step_num}] {reason}")
        return state

    # Ask the LLM to pick from what's left
    prompt = f"""Answer with exactly one word, nothing else.
Modules not yet run: {remaining}
Pick the most sensible one to run next.
One word answer:"""

    response = llm.invoke(prompt)
    raw = response.content.strip().lower()

    action = next((m for m in remaining if m in raw), remaining[0])  # fallback: first remaining
    reason = f"chose '{action}' — next unrun module in the assessment"

    state["decision_log"].append(f"Step {step_num}: {reason}")
    state["_next_action"] = action
    print(f"  [Step {step_num}] {reason}")
    return state

# --- execute_node: output #1 consumed, findings/modules_run updated ---
def execute_node(state: AgentState):
    action = state["_next_action"]
    result = MODULE_RUNNERS[action](state)

    state["findings"].append(result)
    state["modules_run"].append(action)

    if action == "idor_check":
        state["pending_chains"].pop(0)  # this chain has now been consumed

    if result["chain_trigger"]:
        state["pending_chains"].append(result["chain_data"])

    return state

def route_after_decide(state: AgentState):
    return "end" if state["done"] else "execute"

graph = StateGraph(AgentState)
graph.add_node("decide", decide_node)
graph.add_node("execute", execute_node)
graph.set_entry_point("decide")
graph.add_conditional_edges("decide", route_after_decide, {"execute": "execute", "end": END})
graph.add_edge("execute", "decide")
app = graph.compile()

if __name__ == "__main__":
    initial_state = {
        "findings": [], "modules_run": [], "pending_chains": [],
        "_next_action": "", "decision_log": [], "done": False
    }
    final_state = app.invoke(initial_state)

    print("\n--- DECISION LOG (Module 1's full output) ---")
    for line in final_state["decision_log"]:
        print(line)

    print("\nFINAL modules run:", final_state["modules_run"])
    print("FINAL findings count:", len(final_state["findings"]))