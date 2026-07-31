"""
Module 2: Memory & State Management
"""

from typing import TypedDict, List, Dict, Optional


class AgentState(TypedDict):
    target_url: str
    max_steps: int
    chaining_enabled: bool  # NEW — toggle for baseline vs full evaluation

    tech_stack: Dict
    discovered_pages: List[str]
    discovered_params: List[str]

    findings: List[Dict]
    auth_status: Dict

    modules_run: List[str]
    step_count: int
    pending_chain: Optional[Dict]
    done: bool
    _next_action: Optional[str]

    decision_log: List[str]


def initial_state(target_url: str, max_steps: int = 20, chaining_enabled: bool = True) -> AgentState:
    return AgentState(
        target_url=target_url,
        max_steps=max_steps,
        chaining_enabled=chaining_enabled,
        tech_stack={},
        discovered_pages=[],
        discovered_params=[],
        findings=[],
        auth_status={},
        modules_run=[],
        step_count=0,
        pending_chain=None,
        done=False,
        decision_log=[],
        _next_action=None,
    )


def summarize_state(state: AgentState) -> str:
    return f"""
Target: {state['target_url']}
Step: {state['step_count']}/{state['max_steps']}
Tech stack known: {state['tech_stack'] or 'not yet fingerprinted'}
Pages discovered: {len(state['discovered_pages'])}
Modules already run: {state['modules_run'] or 'none yet'}
Findings so far: {len(state['findings'])}
Auth status: {'session obtained' if state['auth_status'].get('session_token') else 'no session yet'}
Pending chain opportunity: {state['pending_chain']}
""".strip()