from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from dotenv import load_dotenv

from state import AgentState, initial_state, summarize_state

from modules.recon import run_fingerprint, run_crawl
from modules.vuln_assess import run_auth_check, run_idor_check, run_sqli_check, run_xss_check
from modules.report import generate_report

load_dotenv()

llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0
)

CORE_MODULES = ["fingerprint", "crawl", "auth_check", "sqli_check", "xss_check"]

MAX_STEPS = 15

MODULE_RUNNERS = {
    "fingerprint": lambda state: run_fingerprint(state),
    "crawl": lambda state: run_crawl(state),
    "auth_check": lambda state: run_auth_check(state),
    "sqli_check": lambda state: run_sqli_check(state),
    "xss_check": lambda state: run_xss_check(state),
    "idor_check": lambda state: run_idor_check(state),
}


def decide_node(state: AgentState):

    step_num = len(state["decision_log"]) + 1

    if step_num > MAX_STEPS:
        reason = "hit max step limit — stopping to avoid infinite loop"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = "stop"
        state["done"] = True
        print(f"  [Step {step_num}] {reason}")
        return state

    if state["pending_chains"] and state["chaining_enabled"]:
        chain = state["pending_chains"][0]
        action = chain["next_module"]
        reason = f"CHAINED into '{action}' because: {chain.get('reason', 'follow-up triggered')}"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = action
        print(f"  [Step {step_num}] {reason}")
        return state

    remaining = [m for m in CORE_MODULES if m not in state["modules_run"]]

    if not remaining:
        reason = "all core modules run, no pending chains — assessment complete"
        state["decision_log"].append(f"Step {step_num}: {reason}")
        state["_next_action"] = "stop"
        state["done"] = True
        print(f"  [Step {step_num}] {reason}")
        return state

    prompt = f"""Current assessment status:

{summarize_state(state)}

Modules not yet run: {remaining}

Answer with exactly one word — pick the most sensible one to run next."""

    response = llm.invoke(prompt)

    raw = response.content.strip().lower()

    action = next(
        (m for m in remaining if m in raw),
        remaining[0]
    )

    reason = f"chose '{action}' — next unrun module in the assessment"

    state["decision_log"].append(
        f"Step {step_num}: {reason}"
    )

    state["_next_action"] = action

    print(f"  [Step {step_num}] {reason}")

    return state


def execute_node(state: AgentState):

    action = state["_next_action"]

    if action == "idor_check" and state["pending_chains"]:
        state["pending_chain"] = state["pending_chains"][0]

    try:
        result = MODULE_RUNNERS[action](state)

    except Exception as e:
        print(f"  [ERROR] {action} failed: {e}")

        result = {
            "finding_type": "error",
            "data": {"error": str(e)},
            "chain_trigger": False,
            "chain_data": None
        }

    state["findings"].append(result)
    state["modules_run"].append(action)
    state["step_count"] += 1

    if action == "fingerprint" and "tech_stack" in result.get("data", {}):
        state["tech_stack"] = result["data"]["tech_stack"]

    if action == "idor_check" and state["pending_chains"]:
        state["pending_chains"].pop(0)
        state["pending_chain"] = None

    if result["chain_trigger"]:
        state["pending_chains"].append(result["chain_data"])

    return state


def route_after_decide(state: AgentState):

    return "end" if state["done"] else "execute"


graph = StateGraph(AgentState)

graph.add_node("decide", decide_node)
graph.add_node("execute", execute_node)

graph.set_entry_point("decide")

graph.add_conditional_edges(
    "decide",
    route_after_decide,
    {
        "execute": "execute",
        "end": END
    }
)

graph.add_edge("execute", "decide")

app = graph.compile()


if __name__ == "__main__":

    state = initial_state("http://localhost:3000")

    final_state = app.invoke(state)

    print("\n--- ALL FINDINGS ---")

    for f in final_state["findings"]:
        print(f"[{f['finding_type']}] {f['data']}")

    print("\n" + generate_report(final_state))