import json

from agent import update_state_after_module
from state import initial_state


def _chain_result(data):
    return {
        "chain_trigger": True,
        "chain_data": {"chain": "sqli_to_idor", "next_module": "idor_check"},
        "data": data,
    }


def test_sqli_chain_trigger_confirmed():
    """Confirmed SQL injection (explicit SQL error) triggers the chain."""
    state = initial_state("http://localhost:3000")
    result = _chain_result({
        "confirmed": True,
        "vulnerable": True,
        "authenticated": True,
    })
    update_state_after_module(state, "sqli_check", result, "confirmed SQLi")
    assert state.get("pending_chain") is not None
    assert state["pending_chain"]["chain"] == "sqli_to_idor"
    assert state["metrics"]["chains_triggered"] == 1


def test_sqli_chain_trigger_bypass_verified():
    """
    A genuinely verified SQLi-caused authentication bypass (benign control
    failed, injection payload authenticated) triggers the chain even without
    an explicit SQL error.
    """
    state = initial_state("http://localhost:3000")
    result = _chain_result({
        "confirmed": False,
        "vulnerable": True,
        "authentication_bypass_verified": True,
        "authenticated": True,
    })
    update_state_after_module(state, "sqli_check", result, "verified SQLi bypass")
    assert state.get("pending_chain") is not None
    assert state["pending_chain"]["chain"] == "sqli_to_idor"
    assert state["metrics"]["chains_triggered"] == 1


def test_sqli_chain_trigger_ordinary_login_does_not_trigger():
    """An ordinary successful login (no verified injection bypass) must NOT trigger."""
    state = initial_state("http://localhost:3000")
    result = _chain_result({
        "confirmed": False,
        "vulnerable": True,
        "authenticated": True,
        "authentication_bypass_verified": False,
    })
    update_state_after_module(state, "sqli_check", result, "ordinary login")
    assert state.get("pending_chain") is None
    assert state["metrics"]["chains_triggered"] == 0


def test_sqli_chain_trigger_unverified_cookie_does_not_trigger():
    """A lone session cookie / token, with no verified bypass, must NOT trigger."""
    state = initial_state("http://localhost:3000")
    result = _chain_result({
        "confirmed": False,
        "vulnerable": False,
        "authenticated": False,
        "authentication_bypass_verified": False,
        "token_found": True,
        "token_source": "cookie",
    })
    update_state_after_module(state, "sqli_check", result, "unverified cookie")
    assert state.get("pending_chain") is None
    assert state["metrics"]["chains_triggered"] == 0


def test_chain_session_token_redacted_from_findings():
    """
    The authenticated session is retained in pending_chain for the IDOR step,
    but the raw token must never appear anywhere in state["findings"].
    """
    state = initial_state("http://localhost:3000")
    result = {
        "chain_trigger": True,
        "chain_data": {
            "chain": "sqli_to_idor",
            "next_module": "idor_check",
            "authenticated_session": {"token": "SECRET-TOKEN-123"},
            "auth_token_found": True,
            "auth_token_source": "cookie",
        },
        "data": {
            "confirmed": False,
            "authentication_bypass_verified": True,
        },
    }
    update_state_after_module(state, "sqli_check", result, "verified bypass")

    # Internal session preserved for the follow-up IDOR assessment.
    assert state["pending_chain"]["authenticated_session"]["token"] == "SECRET-TOKEN-123"

    # No finding may carry the raw token.
    assert "SECRET-TOKEN-123" not in json.dumps(state["findings"])
