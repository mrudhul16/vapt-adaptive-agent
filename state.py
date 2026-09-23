from typing import TypedDict, List, Optional


class AgentState(TypedDict):
    target_url: str
    tech_stack: dict
    pages: List[str]
    findings: List[dict]
    modules_run: List[str]
    pending_chains: List[dict]
    pending_chain: Optional[dict]
    _next_action: str
    decision_log: List[str]
    done: bool
    step_count: int
    chaining_enabled: bool


def initial_state(target_url: str, chaining_enabled: bool = True) -> AgentState:
    return {
        "target_url": target_url,
        "tech_stack": {},
        "pages": [],
        "findings": [],
        "modules_run": [],
        "pending_chains": [],
        "pending_chain": None,
        "_next_action": "",
        "decision_log": [],
        "done": False,
        "step_count": 0,
        "chaining_enabled": chaining_enabled,
    }


def summarize_state(state: AgentState) -> str:
    lines = []

    lines.append(f"Target: {state['target_url']}")

    if state["tech_stack"]:
        lines.append(
            f"Tech stack identified: {state['tech_stack']}"
        )

    lines.append(
        f"Modules already run: {state['modules_run'] or 'none yet'}"
    )

    lines.append(
        f"Pending chains: {len(state['pending_chains'])}"
    )

    lines.append(
        f"Total findings so far: {len(state['findings'])}"
    )

    return "\n".join(lines)