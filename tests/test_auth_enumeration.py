"""Auth user-enumeration detector (security-question endpoint), detection-only."""

import tools.auth_tools as auth_tools
from tools.auth_tools import (
    analyze_security_question,
    detect_security_question_enumeration,
)


class _Resp:
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status


class _FakeSession:
    """Mimics Juice Shop: a real email discloses the security question;
    any other email returns an empty object."""

    REAL = {"admin@juice-sh.op"}

    def get(self, endpoint, params=None, timeout=None):
        email = (params or {}).get("email", "")
        if email in self.REAL:
            return _Resp('{"question":{"id":2,"question":"Mother\'s maiden name?"}}')
        return _Resp("{}")


def test_analyze_flags_disclosed_question():
    disclosed = analyze_security_question(
        _Resp('{"question":{"id":2,"question":"Pet name?"}}')
    )
    assert disclosed["security_question_disclosed"] is True

    empty = analyze_security_question(_Resp("{}"))
    assert empty["security_question_disclosed"] is False


def test_enumeration_detected_with_real_candidate(monkeypatch):
    monkeypatch.setattr(auth_tools, "create_session", lambda: _FakeSession())

    result = detect_security_question_enumeration(
        "http://localhost:3000",
        candidate_emails=["admin@juice-sh.op"],
    )
    assert result["enumeration_detected"] is True
    assert result["security_question_disclosed"] is True
    assert "admin@juice-sh.op" in result["disclosed_for"]


def test_no_enumeration_without_real_candidate(monkeypatch):
    monkeypatch.setattr(auth_tools, "create_session", lambda: _FakeSession())

    # Only non-existent candidates -> no observable difference -> no finding.
    result = detect_security_question_enumeration(
        "http://localhost:3000",
        candidate_emails=["ghost@nowhere.example"],
    )
    assert result["enumeration_detected"] is False


def test_no_candidates_is_honest_negative(monkeypatch):
    monkeypatch.setattr(auth_tools, "create_session", lambda: _FakeSession())

    result = detect_security_question_enumeration("http://localhost:3000")
    assert result["enumeration_detected"] is False
    assert result["candidates_tested"] == 0


def test_harvest_emails_from_recon_blob():
    recon = {
        "observations": [
            {"detail": "found admin@juice-sh.op and jim@juice-sh.op in /api/Users"}
        ]
    }
    emails = auth_tools._harvest_emails(recon)
    assert "admin@juice-sh.op" in emails
    assert "jim@juice-sh.op" in emails
    # .invalid controls are never treated as real candidates
    assert all(not e.endswith(".invalid") for e in emails)
