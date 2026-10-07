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

    recon_state: Dict[str, Any]

    xss_state: Dict[str, Any]

    sqli_state: Dict[str, Any]

    idor_state: Dict[str, Any]


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

        "assessment_start_time": datetime.now().isoformat(),

        "recon_state": {
            "discovered_targets": [],
            "tested_targets": [],
            "interesting_targets": [],
            "remaining_targets": [],

            "observations": [],

            "technologies": [],
            "endpoints": [],
            "forms": [],
            "parameters": [],

            "api_endpoints": [],
            "auth_endpoints": [],
            "user_endpoints": [],
            "transaction_endpoints": [],
            "page_endpoints": [],
            "js_assets": [],
            "other_endpoints": [],

            "attack_surface": {
                "authentication": [],
                "authorization": [],
                "user_data": [],
                "transactions": [],
                "injection": [],
                "client_side": [],
                "other": []
            },

            "iteration": 0,
            "completed": False
        },

        "xss_state": {
            "discovered_targets": [],
            "tested_targets": [],
            "successful_targets": [],
            "remaining_targets": [],
            "observations": [],
            "current_target": None,
            "iteration": 0,
            "completed": False
        },

        "sqli_state": {
            "discovered_targets": [],
            "tested_targets": [],
            "successful_targets": [],
            "remaining_targets": [],
            "observations": [],
            "current_target": None,
            "iteration": 0,
            "completed": False
        },

        "idor_state": {
            "discovered_targets": [],
            "tested_targets": [],
            "successful_targets": [],
            "remaining_targets": [],
            "observations": [],
            "current_target": None,
            "iteration": 0,
            "completed": False,
            "authenticated_session": {}
        }
    }


def summarize_state(state: AgentState) -> str:

    lines = []

    lines.append(
        f"Target: {state['target_url']}"
    )

    if state["tech_stack"]:

        lines.append(
            f"Tech stack identified: "
            f"{state['tech_stack']}"
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

    recon = state.get("recon_state", {})

    lines.append(
        f"Recon targets discovered: "
        f"{len(recon.get('discovered_targets', []))}"
    )

    lines.append(
        f"Recon targets tested: "
        f"{len(recon.get('tested_targets', []))}"
    )

    lines.append(
        f"Recon endpoints discovered: "
        f"{len(recon.get('endpoints', []))}"
    )

    lines.append(
        f"Recon attack surface entries: "
        f"{sum(len(v) for v in recon.get('attack_surface', {}).values())}"
    )

    lines.append(
        f"Workflow steps: "
        f"{state['step_count']}"
    )

    return "\n".join(lines)