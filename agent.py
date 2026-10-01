from langgraph.graph import StateGraph, END
from langchain_groq import ChatGroq
from dotenv import load_dotenv

from state import AgentState, initial_state, summarize_state

from modules.recon import run_fingerprint, run_crawl
from modules.vuln_assess import (
    run_auth_check,
    run_idor_check,
    run_sqli_check,
    run_xss_check
)

from modules.report import generate_report
from modules.risk_engine import analyze_all


load_dotenv()


llm = ChatGroq(
    model="openai/gpt-oss-120b",
    temperature=0
)


CORE_MODULES = [
    "fingerprint",
    "crawl",
    "auth_check",
    "sqli_check",
    "xss_check"
]


MAX_STEPS = 15


MODULE_RUNNERS = {
    "fingerprint": lambda state: run_fingerprint(state),
    "crawl": lambda state: run_crawl(state),
    "auth_check": lambda state: run_auth_check(state),
    "sqli_check": lambda state: run_sqli_check(state),
    "xss_check": lambda state: run_xss_check(state),
    "idor_check": lambda state: run_idor_check(state),
}


def add_decision(
    state: AgentState,
    step: int,
    candidates: list,
    selected: str,
    reason: str
):

    state["decision_history"].append({
        "step": step,
        "candidates": candidates.copy(),
        "selected": selected,
        "reason": reason
    })

    state["decision_log"].append(
        f"Step {step}: {reason}"
    )


def decide_node(state: AgentState):

    step_num = len(state["decision_log"]) + 1

    if step_num > MAX_STEPS:

        reason = (
            "hit max step limit — "
            "stopping to avoid infinite loop"
        )

        add_decision(
            state,
            step_num,
            [],
            "stop",
            reason
        )

        state["_next_action"] = "stop"
        state["done"] = True

        print(f"[Step {step_num}] {reason}")

        return state

    # Adaptive chain has highest priority
    if (
        state["pending_chains"]
        and state["chaining_enabled"]
    ):

        chain = state["pending_chains"][0]

        action = chain["next_module"]

        reason = (
            f"CHAINED into '{action}' because: "
            f"{chain.get('reason', 'follow-up triggered')}"
        )

        add_decision(
            state,
            step_num,
            [action],
            action,
            reason
        )

        state["_next_action"] = action

        print(
            f"[Step {step_num}] {reason}"
        )

        return state

    # Find modules that have not run yet
    remaining = [
        module
        for module in CORE_MODULES
        if module not in state["modules_run"]
    ]

    # Assessment finished
    if not remaining:

        reason = (
            "all core modules run, "
            "no pending chains — assessment complete"
        )

        add_decision(
            state,
            step_num,
            [],
            "stop",
            reason
        )

        state["_next_action"] = "stop"
        state["done"] = True

        print(
            f"[Step {step_num}] {reason}"
        )

        return state

    prompt = f"""
You are the orchestration engine for a controlled
web application security assessment.

Current assessment status:

{summarize_state(state)}

Modules not yet run:

{remaining}

Select the most sensible next module from the
available modules.

Return ONLY one module name.
"""

    try:

        response = llm.invoke(prompt)

        raw = response.content.strip().lower()

    except Exception as e:

        print(
            f"[LLM ERROR] {e}"
        )

        raw = ""

    action = next(
        (
            module
            for module in remaining
            if module in raw
        ),
        remaining[0]
    )

    reason = (
        f"selected '{action}' "
        f"from remaining assessment modules"
    )

    add_decision(
        state,
        step_num,
        remaining,
        action,
        reason
    )

    state["_next_action"] = action

    print(
        f"[Step {step_num}] {reason}"
    )

    return state


def execute_node(state: AgentState):

    action = state["_next_action"]

    # Prepare active chain
    if (
        action == "idor_check"
        and state["pending_chains"]
    ):

        state["pending_chain"] = (
            state["pending_chains"][0]
        )

        state["pending_chain"]["status"] = (
            "executing"
        )

    # Execute module
    try:

        result = MODULE_RUNNERS[action](state)

    except Exception as e:

        print(
            f"[ERROR] {action} failed: {e}"
        )

        result = {
            "finding_type": "error",

            "data": {
                "error": str(e)
            },

            "chain_trigger": False,

            "chain_data": None
        }

    # Store finding
    state["findings"].append(result)

    # Store executed module
    if action not in state["modules_run"]:
        state["modules_run"].append(action)

    # Update metrics
    state["step_count"] += 1

    state["metrics"]["workflow_steps"] += 1

    state["metrics"]["modules_executed"] = (
        len(state["modules_run"])
    )

    state["metrics"]["findings_discovered"] = (
        len(state["findings"])
    )

    # Store discovered pages
    if action == "crawl":

        discovered_pages = (
            result
            .get("data", {})
            .get("discovered_pages", [])
        )

        state["pages"].extend(
            page
            for page in discovered_pages
            if page not in state["pages"]
        )

    # Store fingerprint information
    if action == "fingerprint":

        tech_stack = (
            result
            .get("data", {})
            .get("tech_stack")
        )

        if tech_stack:
            state["tech_stack"] = tech_stack

    # Complete current chain
    if (
        action == "idor_check"
        and state["pending_chains"]
    ):

        chain = state["pending_chains"].pop(0)

        chain["status"] = "completed"

        state["chain_history"].append(chain)

        state["metrics"]["chains_completed"] += 1

        state["pending_chain"] = None

        print(
            "[CHAIN COMPLETED] "
            f"{chain.get('next_module')}"
        )

    # Check for newly triggered chain
    if result.get("chain_trigger"):

        chain_data = result.get(
            "chain_data"
        )

        if chain_data:

            next_module = chain_data.get(
                "next_module"
            )

            if next_module:

                chain_data = chain_data.copy()

                chain_data["status"] = "pending"

                already_run = (
                    next_module
                    in state["modules_run"]
                )

                already_pending = any(
                    chain.get("next_module")
                    == next_module
                    for chain
                    in state["pending_chains"]
                )

                if (
                    not already_run
                    and not already_pending
                ):

                    state["pending_chains"].append(
                        chain_data
                    )

                    state["metrics"][
                        "chains_triggered"
                    ] += 1

                    print(
                        "[CHAIN TRIGGERED] "
                        f"{action} → {next_module}"
                    )

                else:

                    print(
                        "[CHAIN SKIPPED] "
                        f"'{next_module}' "
                        "already run or pending"
                    )

    # Update risk assessments
    state["risk_assessments"] = analyze_all(
        state["findings"]
    )

    return state


def route_after_decide(state: AgentState):

    if state["done"]:
        return "end"

    return "execute"


graph = StateGraph(AgentState)


graph.add_node(
    "decide",
    decide_node
)

graph.add_node(
    "execute",
    execute_node
)


graph.set_entry_point(
    "decide"
)


graph.add_conditional_edges(
    "decide",
    route_after_decide,
    {
        "execute": "execute",
        "end": END
    }
)


graph.add_edge(
    "execute",
    "decide"
)


app = graph.compile()


if __name__ == "__main__":

    state = initial_state(
        "http://localhost:3000"
    )

    final_state = app.invoke(
        state
    )

    print(
        "\n--- ALL FINDINGS ---"
    )

    for finding in final_state["findings"]:

        print(
            f"[{finding['finding_type']}] "
            f"{finding['data']}"
        )

    print(
        "\n--- ADAPTIVE CHAINS ---"
    )

    for chain in final_state[
        "chain_history"
    ]:

        print(
            f"{chain.get('reason')} → "
            f"{chain.get('next_module')} "
            f"[{chain.get('status')}]"
        )

    print(
        "\n--- RISK ASSESSMENTS ---"
    )

    for risk in final_state[
        "risk_assessments"
    ]:

        print(
            f"[{risk['severity']}] "
            f"{risk['title']} | "
            f"Confidence: {risk['confidence']}"
        )

    print(
        "\n--- METRICS ---"
    )

    for key, value in final_state[
        "metrics"
    ].items():

        print(
            f"{key}: {value}"
        )

    print(
        "\n--- DECISION HISTORY ---"
    )

    for decision in final_state[
        "decision_history"
    ]:

        print(
            decision
        )

    print(
        "\n" + generate_report(
            final_state
        )
    )