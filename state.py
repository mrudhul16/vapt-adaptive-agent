from typing import TypedDict, List, Optional, Dict, Any
from datetime import datetime


class AgentState(TypedDict):
    target_url: str

    tech_stack: dict
    pages: List[str]

    findings: List[dict]
    risk_assessments: List[dict]

    modules_run: List[str]

    pending_chains: List[dict]
    pending_chain: Optional[dict]
    chain_history: List[dict]

    _next_action: str

    decision_log: List[str]
    decision_history: List[dict]

    done: bool
    step_count: int
    chaining_enabled: bool

    metrics: Dict[str, Any]

    assessment_start_time: str


def initial_state(
    target_url: str,
    chaining_enabled: bool = True
) -> AgentState:

    return {
        "target_url": target_url,

        "tech_stack": {},
        "pages": [],

        "findings": [],
        "risk_assessments": [],

        "modules_run": [],

        "pending_chains": [],
        "pending_chain": None,
        "chain_history": [],

        "_next_action": "",

        "decision_log": [],
        "decision_history": [],

        "done": False,
        "step_count": 0,
        "chaining_enabled": chaining_enabled,

        "metrics": {
            "modules_executed": 0,
            "findings_discovered": 0,
            "chains_triggered": 0,
            "chains_completed": 0,
            "workflow_steps": 0
        },

        "assessment_start_time": datetime.now().isoformat()
    }


def summarize_state(state: AgentState) -> str:

    lines = []

    lines.append(
        f"Target: {state['target_url']}"
    )

    if state["tech_stack"]:
        lines.append(
            f"Tech stack identified: {state['tech_stack']}"
        )

    lines.append(
        f"Modules already run: "
        f"{state['modules_run'] or 'none yet'}"
    )

    lines.append(
        f"Pending chains: "
        f"{len(state['pending_chains'])}"
    )

    lines.append(
        f"Completed chains: "
        f"{state['metrics']['chains_completed']}"
    )

    lines.append(
        f"Total findings so far: "
        f"{len(state['findings'])}"
    )

    lines.append(
        f"Workflow steps: "
        f"{state['step_count']}"
    )

    return "\n".join(lines)