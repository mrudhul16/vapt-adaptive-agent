"""Baseline (non-adaptive) mode: fixed linear order, no LLM, no chaining —
the control the adaptive mode is compared against."""

import agent
from state import initial_state


class _FakeLLM:
    def __init__(self):
        self.called = False

    def invoke(self, *a, **k):
        self.called = True
        raise AssertionError("baseline mode must not call the LLM")


def _baseline_state(executed):
    s = initial_state("http://localhost:3000")
    s["chaining_enabled"] = False
    s["modules_run"] = executed
    return s


def test_baseline_runs_core_modules_in_fixed_order(monkeypatch):
    fake = _FakeLLM()
    monkeypatch.setattr(agent, "llm", fake)

    # recon first
    assert agent.decide_next_module(initial_state("http://localhost:3000") | {"chaining_enabled": False})["action"] == "recon"
    # then the remaining core modules, in order, with no LLM calls
    assert agent.decide_next_module(_baseline_state(["recon"]))["action"] == "auth"
    assert agent.decide_next_module(_baseline_state(["recon", "auth"]))["action"] == "sqli_check"
    assert agent.decide_next_module(_baseline_state(["recon", "auth", "sqli_check"]))["action"] == "xss_check"
    assert agent.decide_next_module(_baseline_state(["recon", "auth", "sqli_check", "xss_check"]))["action"] == "authorization"
    # all core modules done -> stop (IDOR is never selected in baseline)
    done = ["recon", "auth", "sqli_check", "xss_check", "authorization"]
    assert agent.decide_next_module(_baseline_state(done))["action"] == "stop"
    assert fake.called is False


def test_baseline_never_selects_idor():
    for executed in (
        ["recon"],
        ["recon", "sqli_check"],
        ["recon", "auth", "sqli_check", "xss_check"],
    ):
        action = agent.decide_next_module(_baseline_state(executed))["action"]
        assert action != "idor_check"


def test_baseline_does_not_trigger_chain():
    """Even a confirmed SQLi must not set a pending chain when chaining is off."""
    s = initial_state("http://localhost:3000")
    s["chaining_enabled"] = False
    result = {
        "chain_trigger": True,
        "chain_data": {"chain": "sqli_to_idor", "next_module": "idor_check"},
        "data": {"confirmed": True, "vulnerable": True},
    }
    agent.update_state_after_module(s, "sqli_check", result, "confirmed SQLi")
    assert s.get("pending_chain") is None
    assert s["metrics"]["chains_triggered"] == 0


def test_adaptive_still_triggers_chain():
    s = initial_state("http://localhost:3000")  # chaining_enabled defaults True
    result = {
        "chain_trigger": True,
        "chain_data": {"chain": "sqli_to_idor", "next_module": "idor_check"},
        "data": {"confirmed": True, "vulnerable": True},
    }
    agent.update_state_after_module(s, "sqli_check", result, "confirmed SQLi")
    assert s.get("pending_chain") is not None
    assert s["metrics"]["chains_triggered"] == 1
