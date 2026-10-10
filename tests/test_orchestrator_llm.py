"""Genuine LLM-driven orchestration: the graph ranks, the LLM chooses, with
deterministic guarantees for recon-first and verified chains, plus validation."""

import agent
from modules.attack_graph import AttackGraph
from state import initial_state


class _Resp:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    """Stand-in for agent.llm (a pydantic model whose methods can't be patched)."""
    def __init__(self, content=None, raises=None):
        self._content = content
        self._raises = raises
        self.called = False

    def invoke(self, *a, **k):
        self.called = True
        if self._raises:
            raise self._raises
        return _Resp(self._content)


def _state_with_surface():
    s = initial_state("http://localhost:3000")
    g = AttackGraph()
    g.add_node("injection:0", "injection", {"url": "/x"})
    g.add_node("client_side:0", "client_side", {"url": "/#/s"})
    g.add_node("authentication:0", "authentication", {"url": "/login"})
    g.add_node("user_data:0", "user_data", {"url": "/rest/basket/1"})
    g.infer_relationships()
    s["attack_graph"] = g
    s["modules_run"] = ["recon"]  # past the recon-first guard
    return s


def test_recon_runs_first_deterministically():
    s = initial_state("http://localhost:3000")
    s["modules_run"] = []
    assert agent.decide_next_module(s)["action"] == "recon"


def test_pending_chain_is_deterministic_no_llm(monkeypatch):
    s = _state_with_surface()
    s["pending_chain"] = {"chain": "sqli_to_idor", "next_module": "idor_check"}
    fake = _FakeLLM(raises=AssertionError("LLM must not be called"))
    monkeypatch.setattr(agent, "llm", fake)
    assert agent.decide_next_module(s)["action"] == "idor_check"
    assert fake.called is False  # chain is deterministic, no LLM call


def test_llm_choice_is_honored(monkeypatch):
    s = _state_with_surface()
    monkeypatch.setattr(agent, "llm",
                        _FakeLLM('{"action":"xss_check","reason":"client-side surface"}'))
    d = agent.decide_next_module(s)
    assert d["action"] == "xss_check"  # LLM genuinely picked, not forced to top score


def test_invalid_llm_choice_falls_back_to_graph(monkeypatch):
    s = _state_with_surface()
    monkeypatch.setattr(agent, "llm", _FakeLLM('{"action":"not_a_module","reason":"x"}'))
    d = agent.decide_next_module(s)
    assert d["action"] in {m for m in agent.CORE_MODULES} | {"idor_check"}


def test_llm_error_falls_back(monkeypatch):
    s = _state_with_surface()
    monkeypatch.setattr(agent, "llm", _FakeLLM(raises=RuntimeError("boom")))
    d = agent.decide_next_module(s)
    assert d["action"] in {m for m in agent.CORE_MODULES} | {"idor_check"}


def test_shortlist_excludes_executed_and_suppresses_idor_without_session():
    s = _state_with_surface()
    short = agent.get_graph_shortlist(s)
    actions = {x["action"] for x in short}
    assert "recon" not in actions           # already executed
    assert "idor_check" not in actions       # no session yet -> score 0
    assert "sqli_check" in actions
