"""AI-authored executive summary: uses the LLM when available, falls back
deterministically, and never leaks raw sessions/tokens."""

import json

import agent
from state import initial_state


class _Resp:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, content=None, raises=None):
        self._content, self._raises = content, raises

    def invoke(self, *a, **k):
        if self._raises:
            raise self._raises
        return _Resp(self._content)


def _findings_state():
    s = initial_state("http://localhost:3000")
    s["modules_run"] = ["recon", "sqli_check", "idor_check"]
    s["metrics"]["chains_triggered"] = 1
    s["metrics"]["chains_completed"] = 1
    s["sqli_state"] = {"successful_targets": [{"url": "/#/login"}], "confirmed_vulnerabilities": []}
    s["idor_state"] = {"successful_targets": [
        {"target": {"url": "http://localhost:3000/rest/basket/2"}},
        {"target": {"url": "http://localhost:3000/rest/basket/3"}},
    ]}
    s["xss_state"] = {"confirmed_vulnerabilities": [], "potential_findings": [{"endpoint": "/main.js"}], "successful_targets": []}
    return s


def test_llm_summary_is_used(monkeypatch):
    s = _findings_state()
    monkeypatch.setattr(agent, "llm", _FakeLLM("The target has critical SQLi and confirmed IDOR."))
    text = agent.generate_executive_summary(s)
    assert "critical SQLi" in text
    assert s["executive_summary"] == text


def test_fallback_summary_when_llm_fails(monkeypatch):
    s = _findings_state()
    monkeypatch.setattr(agent, "llm", _FakeLLM(raises=RuntimeError("down")))
    text = agent.generate_executive_summary(s)
    assert text  # never empty
    assert "IDOR" in text and "cross-user" in text.lower()


def test_empty_llm_output_falls_back(monkeypatch):
    s = _findings_state()
    monkeypatch.setattr(agent, "llm", _FakeLLM("   "))
    text = agent.generate_executive_summary(s)
    assert len(text) > 20


def test_json_wrapped_summary_is_unwrapped(monkeypatch):
    s = _findings_state()
    monkeypatch.setattr(agent, "llm",
                        _FakeLLM('{"summary":"Plain prose risk narrative here."}'))
    text = agent.generate_executive_summary(s)
    assert text == "Plain prose risk narrative here."
    assert not text.startswith("{")


def test_unwrap_summary_helper():
    assert agent._unwrap_summary_text('{"summary":"hello world"}') == "hello world"
    assert agent._unwrap_summary_text("just prose") == "just prose"
    assert agent._unwrap_summary_text('{"narrative":"n"}') == "n"


def test_digest_has_no_session_or_token():
    s = _findings_state()
    # inject a session that must NOT appear in the digest
    s["idor_state"]["authenticated_session"] = {"token": "SECRET-XYZ"}
    s["pending_chain"] = {"authenticated_session": {"token": "SECRET-XYZ"}}
    digest = agent._assessment_digest(s)
    blob = json.dumps(digest)
    assert "SECRET-XYZ" not in blob
    assert "token" not in blob.lower()
