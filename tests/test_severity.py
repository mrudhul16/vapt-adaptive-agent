"""Computed severity: impact x confidence + context, not a hardcoded label."""

from modules.risk_engine import compute_severity


def lvl(cat, status="confirmed", **ctx):
    return compute_severity(cat, status, ctx)["label"]


def test_confirmed_outranks_potential_same_type():
    confirmed = compute_severity("xss", "confirmed")["score"]
    suspected = compute_severity("xss", "suspected")["score"]
    potential = compute_severity("xss", "potential")["score"]
    assert confirmed > suspected > potential


def test_sqli_levels():
    assert lvl("sqli", "confirmed") == "CRITICAL"
    # suspected auth-bypass (control-verified) is still serious -> HIGH
    assert lvl("sqli", "suspected", authentication_bypass_verified=True) == "HIGH"


def test_idor_confirmed_cross_user_is_high():
    assert lvl("idor", "confirmed", cross_user_access=True) == "HIGH"


def test_xss_confidence_bands():
    assert lvl("xss", "confirmed") == "MEDIUM"
    assert lvl("xss", "potential") == "LOW"   # unconfirmed DOM lead


def test_reflected_xss_medium_but_stored_xss_high():
    assert lvl("xss", "confirmed") == "MEDIUM"                    # reflected/DOM
    assert lvl("xss", "confirmed", stored_xss=True) == "HIGH"     # persistent


def test_authorization_excessive_exposure_is_medium():
    assert lvl("authorization", "suspected", multiple_records_exposed=True) == "MEDIUM"


def test_auth_enumeration_is_low():
    assert lvl("auth", "suspected", unauthenticated=True) == "LOW"


def test_recon_is_info():
    assert lvl("recon") == "INFO"
    assert compute_severity("recon")["score"] == 0.0


def test_score_bounded_0_10():
    s = compute_severity("sqli", "confirmed",
                         {"authentication_bypass_verified": True,
                          "cross_user_access": True,
                          "multiple_records_exposed": True,
                          "unauthenticated": True})
    assert 0.0 <= s["score"] <= 10.0
    assert s["label"] == "CRITICAL"
