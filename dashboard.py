import streamlit as st
import copy
import html as html_module
from datetime import datetime
from agent import run_agent
from modules.risk_engine import compute_severity

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="Adaptive AI Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS THEME
# ============================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

    .stApp {
        font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: #0B0E14;
        color: #E2E8F0;
    }
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Outfit', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
        color: #F8FAFC;
    }
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.2s ease;
        text-transform: uppercase;
        font-size: 0.85rem;
    }
    .stButton>button[kind="primary"] {
        background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 100%);
        border: none;
        box-shadow: 0 4px 15px rgba(139, 92, 246, 0.3);
        color: white;
    }
    .stButton>button[kind="primary"]:hover {
        background: linear-gradient(135deg, #2563EB 0%, #7C3AED 100%);
        box-shadow: 0 6px 20px rgba(139, 92, 246, 0.4);
        transform: translateY(-1px);
    }
    [data-testid="stMetricValue"] {
        font-family: 'Outfit', sans-serif !important;
        font-weight: 700 !important;
        font-size: 2.2rem !important;
        background: linear-gradient(180deg, #FFFFFF 0%, #94A3B8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    [data-testid="stMetricLabel"] {
        font-weight: 500 !important;
        color: #64748B !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.7rem !important;
    }
    hr { border-color: rgba(255, 255, 255, 0.04) !important; }
    div[data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.4);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    }
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}

    /* Custom Components */
    .dash-card {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 20px 24px;
        backdrop-filter: blur(12px);
        margin-bottom: 12px;
    }
    .dash-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 20, 50, 0.6) 100%);
        border: 1px solid rgba(139, 92, 246, 0.15);
        border-radius: 16px;
        padding: 32px 36px;
        margin-bottom: 28px;
    }
    .dash-header h1 {
        font-size: 1.8rem;
        margin: 0 0 4px 0;
        background: linear-gradient(90deg, #60A5FA, #A78BFA);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .dash-header .subtitle {
        font-size: 0.9rem;
        color: #94A3B8;
        margin: 0 0 20px 0;
        font-weight: 400;
    }
    .header-meta {
        display: flex;
        gap: 32px;
        flex-wrap: wrap;
        margin-top: 16px;
    }
    .header-meta-item {
        display: flex;
        flex-direction: column;
        gap: 2px;
    }
    .header-meta-label {
        font-size: 0.65rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        font-weight: 500;
    }
    .header-meta-value {
        font-size: 0.9rem;
        color: #E2E8F0;
        font-weight: 500;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Severity Badges */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 6px;
        font-size: 0.65rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-family: 'Outfit', sans-serif;
    }
    .badge-critical { background: rgba(239,68,68,0.15); color: #F87171; border: 1px solid rgba(239,68,68,0.25); }
    .badge-high { background: rgba(249,115,22,0.15); color: #FB923C; border: 1px solid rgba(249,115,22,0.25); }
    .badge-medium { background: rgba(245,158,11,0.15); color: #FBBF24; border: 1px solid rgba(245,158,11,0.25); }
    .badge-low { background: rgba(59,130,246,0.15); color: #60A5FA; border: 1px solid rgba(59,130,246,0.25); }
    .badge-info { background: rgba(107,114,128,0.12); color: #9CA3AF; border: 1px solid rgba(107,114,128,0.2); }
    .badge-pass { background: rgba(16,185,129,0.15); color: #34D399; border: 1px solid rgba(16,185,129,0.25); }
    .badge-confirmed { background: rgba(239,68,68,0.12); color: #F87171; border: 1px solid rgba(239,68,68,0.2); }

    /* Risk Cards */
    .risk-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 12px;
        transition: border-color 0.2s;
    }
    .risk-card:hover { border-color: rgba(255, 255, 255, 0.12); }
    .risk-card-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;
    }
    .risk-card-title {
        font-size: 1rem;
        font-weight: 600;
        color: #F8FAFC;
        letter-spacing: 0.3px;
    }
    .risk-card-body { font-size: 0.85rem; color: #94A3B8; line-height: 1.6; }
    .risk-card-body strong { color: #CBD5E1; }

    /* Timeline */
    .timeline-container { position: relative; padding-left: 40px; }
    .timeline-container::before {
        content: '';
        position: absolute;
        left: 15px;
        top: 0;
        bottom: 0;
        width: 2px;
        background: linear-gradient(180deg, rgba(96,165,250,0.3) 0%, rgba(139,92,246,0.3) 50%, rgba(16,185,129,0.2) 100%);
    }
    .timeline-item {
        position: relative;
        padding: 12px 0 20px 20px;
    }
    .timeline-dot {
        position: absolute;
        left: -32px;
        top: 14px;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 0.6rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
    }
    .timeline-dot-ok { background: rgba(16,185,129,0.2); color: #34D399; border: 2px solid rgba(16,185,129,0.4); }
    .timeline-dot-vuln { background: rgba(239,68,68,0.2); color: #F87171; border: 2px solid rgba(239,68,68,0.4); }
    .timeline-dot-chain { background: rgba(139,92,246,0.2); color: #A78BFA; border: 2px solid rgba(139,92,246,0.4); }
    .timeline-title { font-size: 0.95rem; font-weight: 600; color: #F8FAFC; margin-bottom: 2px; }
    .timeline-desc { font-size: 0.8rem; color: #94A3B8; margin-bottom: 4px; }
    .timeline-status { font-size: 0.75rem; font-weight: 500; }
    .timeline-status-ok { color: #34D399; }
    .timeline-status-vuln { color: #F87171; }
    .timeline-status-chain { color: #A78BFA; }

    /* Section Titles */
    .sec-title {
        font-size: 1.15rem;
        font-weight: 600;
        color: #F8FAFC;
        margin: 0 0 2px 0;
        letter-spacing: -0.2px;
    }
    .sec-subtitle {
        font-size: 0.8rem;
        color: #64748B;
        margin: 0 0 16px 0;
        font-weight: 400;
    }

    /* Chain Flow */
    .chain-flow {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0;
        margin: 20px 0;
        flex-wrap: wrap;
    }
    .chain-node {
        border-radius: 10px;
        padding: 14px 18px;
        text-align: center;
        min-width: 140px;
        backdrop-filter: blur(8px);
    }
    .chain-node h4 { margin: 0; font-size: 0.85rem; font-weight: 600; color: #F8FAFC; }
    .chain-node p { margin: 4px 0 0; font-size: 0.7rem; color: #94A3B8; }
    .chain-arrow { color: #475569; font-size: 1.2rem; padding: 0 8px; }
    .node-red { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); }
    .node-blue { background: rgba(59,130,246,0.08); border: 1px solid rgba(59,130,246,0.2); }
    .node-purple { background: rgba(139,92,246,0.08); border: 1px solid rgba(139,92,246,0.2); }
    .node-green { background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); }
    .node-amber { background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.2); }

    /* Baseline vs Adaptive */
    .bva-container { display: flex; gap: 24px; margin-bottom: 24px; }
    .bva-card {
        flex: 1;
        border-radius: 14px;
        padding: 24px;
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(12px);
        display: flex;
        flex-direction: column;
    }
    .bva-card.baseline { border: 1px solid rgba(59, 130, 246, 0.15); }
    .bva-card.adaptive { border: 1px solid rgba(16, 185, 129, 0.15); }
    .bva-header-row { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
    .bva-title-col { display: flex; gap: 14px; align-items: center; }
    .bva-icon-box {
        width: 44px; height: 44px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 13px; font-weight: 700; letter-spacing: 1px;
    }
    .baseline .bva-icon-box { background: rgba(59,130,246,0.15); color: #60A5FA; border: 1px solid rgba(59,130,246,0.25); }
    .adaptive .bva-icon-box { background: rgba(16,185,129,0.15); color: #34D399; border: 1px solid rgba(16,185,129,0.25); }
    .bva-title { font-size: 1rem; font-weight: 600; margin: 0; color: #F8FAFC; }
    .bva-subtitle { font-size: 0.75rem; margin: 3px 0 0; text-transform: uppercase; letter-spacing: 1px; }
    .baseline .bva-subtitle { color: #60A5FA; }
    .adaptive .bva-subtitle { color: #34D399; }
    .bva-badge {
        padding: 4px 10px; border-radius: 6px;
        font-size: 0.65rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;
    }
    .baseline .bva-badge { background: rgba(59,130,246,0.1); color: #60A5FA; border: 1px solid rgba(59,130,246,0.2); }
    .adaptive .bva-badge { background: rgba(16,185,129,0.1); color: #34D399; border: 1px solid rgba(16,185,129,0.2); }
    .bva-metric {
        display: flex; justify-content: space-between; align-items: center;
        padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.04);
        font-size: 0.85rem; color: #CBD5E1;
    }
    .bva-metric:last-of-type { border-bottom: none; }
    .bva-metric-val { font-weight: 600; font-size: 0.95rem; color: #F8FAFC; }
    .bva-metric-val.val-red { color: #F87171 !important; }
    .bva-metric-val.val-green { color: #34D399 !important; }
    .bva-metric-val.val-amber { color: #FBBF24 !important; }
    .bva-msg-box {
        margin-top: 16px; padding: 12px 14px; border-radius: 8px;
        font-size: 0.8rem; line-height: 1.5; color: #94A3B8;
    }
    .baseline .bva-msg-box { background: rgba(59,130,246,0.04); border-left: 3px solid rgba(59,130,246,0.3); }
    .adaptive .bva-msg-box { background: rgba(16,185,129,0.04); border-left: 3px solid rgba(16,185,129,0.3); }

    /* Decision Log */
    .decision-step {
        padding: 12px 16px;
        background: rgba(15, 23, 42, 0.3);
        border: 1px solid rgba(255,255,255,0.04);
        border-radius: 8px;
        margin-bottom: 8px;
    }
    .decision-step-num {
        font-size: 0.65rem; font-weight: 700; color: #64748B;
        text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px;
    }
    .decision-step-action { font-size: 0.9rem; font-weight: 600; color: #E2E8F0; margin-bottom: 2px; }
    .decision-step-reason { font-size: 0.8rem; color: #94A3B8; line-height: 1.5; }

    /* Landing Page */
    .landing-card {
        background: rgba(15, 23, 42, 0.4);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 28px;
        text-align: center;
    }
    .landing-card h3 { margin: 0 0 8px; font-size: 1rem; }
    .landing-card p { margin: 0; font-size: 0.85rem; color: #94A3B8; line-height: 1.5; }

    /* ---- Findings & Evidence cards ---- */
    .ev-card {
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(255,255,255,0.06);
        border-left: 4px solid rgba(148,163,184,0.5);
        border-radius: 12px;
        padding: 18px 22px;
        margin-bottom: 14px;
    }
    .ev-card.sev-critical { border-left-color: #F87171; }
    .ev-card.sev-high     { border-left-color: #FB923C; }
    .ev-card.sev-medium   { border-left-color: #FBBF24; }
    .ev-card.sev-low      { border-left-color: #60A5FA; }
    .ev-card.sev-info     { border-left-color: #9CA3AF; }
    .ev-head {
        display: flex; align-items: center; gap: 10px;
        flex-wrap: wrap; margin-bottom: 4px;
    }
    .ev-title { font-size: 1rem; font-weight: 600; color: #F8FAFC; margin: 0; }
    .ev-module {
        font-size: 0.65rem; color: #64748B; text-transform: uppercase;
        letter-spacing: 1.5px; font-weight: 600; margin-left: auto;
        font-family: 'JetBrains Mono', monospace;
    }
    .ev-endpoint {
        font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;
        color: #93C5FD; background: rgba(59,130,246,0.07);
        border: 1px solid rgba(59,130,246,0.12); border-radius: 6px;
        padding: 4px 10px; margin: 8px 0 10px; display: inline-block;
        word-break: break-all;
    }
    .ev-summary { font-size: 0.85rem; color: #94A3B8; line-height: 1.6; margin-bottom: 12px; }
    .ev-grid {
        display: grid; grid-template-columns: 180px 1fr; gap: 6px 16px;
        font-size: 0.82rem; margin-top: 8px;
    }
    .ev-k { color: #64748B; font-weight: 500; }
    .ev-v { color: #E2E8F0; font-family: 'JetBrains Mono', monospace; word-break: break-word; }
    .ev-chip {
        display: inline-block; font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem; padding: 2px 8px; border-radius: 5px; margin: 2px 4px 2px 0;
    }
    .ev-chip.src { background: rgba(249,115,22,0.1); color: #FDBA74; border: 1px solid rgba(249,115,22,0.2); }
    .ev-chip.snk { background: rgba(239,68,68,0.1); color: #FCA5A5; border: 1px solid rgba(239,68,68,0.2); }
    .status-chip {
        display: inline-block; padding: 3px 10px; border-radius: 6px;
        font-size: 0.62rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;
    }
    .status-confirmed { background: rgba(239,68,68,0.15); color: #F87171; border: 1px solid rgba(239,68,68,0.25); }
    .status-suspected { background: rgba(245,158,11,0.15); color: #FBBF24; border: 1px solid rgba(245,158,11,0.25); }
    .status-potential { background: rgba(59,130,246,0.15); color: #60A5FA; border: 1px solid rgba(59,130,246,0.25); }
    .status-info      { background: rgba(107,114,128,0.12); color: #9CA3AF; border: 1px solid rgba(107,114,128,0.2); }
    .ev-empty {
        text-align: center; padding: 40px; color: #475569;
        border: 1px dashed rgba(255,255,255,0.08); border-radius: 12px;
    }
    .sev-summary-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 18px; }
    .sev-pill {
        flex: 1; min-width: 110px; text-align: center; padding: 14px 10px;
        border-radius: 12px; background: rgba(15,23,42,0.6); border: 1px solid rgba(255,255,255,0.06);
    }
    .sev-pill .num { font-size: 1.8rem; font-weight: 700; line-height: 1; font-family: 'Outfit', sans-serif; }
    .sev-pill .lbl { font-size: 0.62rem; text-transform: uppercase; letter-spacing: 1.5px; color: #64748B; margin-top: 6px; }
    .sev-pill.c-critical .num { color: #F87171; }
    .sev-pill.c-high .num { color: #FB923C; }
    .sev-pill.c-medium .num { color: #FBBF24; }
    .sev-pill.c-low .num { color: #60A5FA; }
    .sev-pill.c-potential .num { color: #A78BFA; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

SENSITIVE_KEYS = {
    "token", "jwt", "authorization", "cookie", "session_token",
    "access_token", "refresh_token", "password", "passwd",
    "secret", "credential", "credentials", "bearer",
    "api_key", "apikey", "groq_api_key", "auth_token",
    "authenticated_session", "auth_session",
}

MODULE_DISPLAY = {
    "recon": "Reconnaissance",
    "auth": "Authentication",
    "sqli_check": "SQL Injection",
    "idor_check": "IDOR",
    "xss_check": "XSS",
    "authorization": "Authorization",
    "fingerprint": "Fingerprinting",
    "crawl": "Web Crawling",
}

MODULE_PURPOSE = {
    "recon": "Reconnaissance identifies the application's attack surface, technology stack, and endpoint inventory before active vulnerability testing begins.",
    "auth": "Evaluates whether the application's authentication mechanisms behave securely and whether valid sessions can be established.",
    "sqli_check": "Tests injection points for SQL injection behavior and authentication bypass vulnerabilities.",
    "idor_check": "Tests whether an authenticated user can access resources belonging to another user, confirming authorization boundary violations.",
    "xss_check": "Tests client-side inputs and application endpoints for executable cross-site scripting behavior.",
    "authorization": "Tests whether protected resources enforce correct authorization boundaries and access controls.",
}

SEVERITY_MAP = {
    "sqli": ("CRITICAL", "badge-critical"),
    "idor": ("HIGH", "badge-high"),
    "xss": ("MEDIUM", "badge-medium"),
    "auth": ("LOW", "badge-low"),
    "authorization": ("LOW", "badge-low"),
    "recon": ("INFO", "badge-info"),
    "fingerprint": ("INFO", "badge-info"),
    "crawl": ("INFO", "badge-info"),
}

FINDING_TO_MODULE = {
    "recon": "recon",
    "auth": "auth",
    "sqli": "sqli_check",
    "idor": "idor_check",
    "xss": "xss_check",
    "authorization": "authorization",
}


def redact_sensitive(data):
    """Recursively redact sensitive fields from data structures."""
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(s in key_lower for s in SENSITIVE_KEYS):
                cleaned[key] = "[REDACTED]"
            elif isinstance(value, (dict, list)):
                cleaned[key] = redact_sensitive(value)
            elif isinstance(value, str) and len(value) > 50 and ("ey" in value[:5] or "Bearer" in value):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = value
        return cleaned
    elif isinstance(data, list):
        return [
            redact_sensitive(item) if isinstance(item, (dict, list)) else item
            for item in data
        ]
    return data


def get_severity(category):
    """Severity label + badge class for a risk CATEGORY (aggregate view).

    Uses the computed severity model at a 'confirmed' baseline, since risk
    categories are only listed when a vulnerability of that type was found.
    Per-finding cards use the full confidence/context-aware computation.
    """
    sev = compute_severity(category, "confirmed")
    return (sev["label"], sev["badge"])


def is_finding_vulnerable(finding):
    """Check if a finding represents a confirmed vulnerability."""
    if finding.get("vulnerable") is True:
        return True
    data = finding.get("data", {})
    if isinstance(data, dict):
        if data.get("vulnerable") is True:
            return True
        findings_list = data.get("findings")
        if isinstance(findings_list, list) and len(findings_list) > 0:
            return True
    return False


def count_vulnerabilities(findings):
    """Count confirmed vulnerabilities from findings."""
    return [f for f in findings if is_finding_vulnerable(f)]


def get_finding_status(finding):
    """Get a human-readable status for a finding."""
    if is_finding_vulnerable(finding):
        return "CONFIRMED", "badge-confirmed"
    finding_type = finding.get("finding_type", "")
    if finding_type in ("recon", "fingerprint", "crawl"):
        return "INFORMATIONAL", "badge-info"
    return "PASS", "badge-pass"


def safe_get_list_len(data, key, default=0):
    """Safely get the length of a list from a dict."""
    val = data.get(key, [])
    if isinstance(val, list):
        return len(val)
    return default


# ------------------------------------------------------------
# Findings & Evidence normalization
# ------------------------------------------------------------
_SEV = {
    "sqli": ("CRITICAL", "sev-critical"),
    "idor": ("HIGH", "sev-high"),
    "xss": ("MEDIUM", "sev-medium"),
    "auth": ("LOW", "sev-low"),
    "authorization": ("LOW", "sev-low"),
}


def _d(obj):
    return obj if isinstance(obj, dict) else {}


def build_evidence_findings(state):
    """Normalize all module results into professional, evidence-backed cards.

    Defensive by design: unknown shapes simply produce fewer cards (the raw
    JSON expander remains available as a fallback). Secrets are never surfaced.
    """
    findings = state.get("findings", []) or []
    xss_state = _d(state.get("xss_state"))
    idor_state = _d(state.get("idor_state"))
    items = []

    # ---- SQL Injection (module-level) ----
    for f in findings:
        ft = str(f.get("finding_type") or f.get("category") or "").lower()
        if ft != "sqli":
            continue
        data = _d(f.get("data"))
        if not (f.get("vulnerable") or data.get("vulnerable")):
            continue
        confirmed = data.get("confirmed") is True
        bypass = data.get("authentication_bypass_verified") is True
        payload = None
        for obs in data.get("observations", []) or []:
            if isinstance(obs, dict) and obs.get("authentication_bypass_verified"):
                payload = obs.get("payload")
                break
        ev = []
        if payload:
            ev.append(("Injection payload", payload))
        ev.append((
            "Authentication bypass",
            "Verified — benign control failed while the injection authenticated"
            if bypass else "Not independently verified",
        ))
        if data.get("auth_token_source"):
            ev.append(("Session token obtained via",
                       f"{data.get('auth_token_source')} (value redacted)"))
        tgt = _d(data.get("target"))
        items.append({
            "title": "SQL Injection — Authentication Bypass",
            "module": "SQL Injection",
            "category": "sqli",
            "context": {"authentication_bypass_verified": bypass},
            "status": ("CONFIRMED", "status-confirmed") if confirmed
            else ("SUSPECTED", "status-suspected"),
            "endpoint": tgt.get("url") or state.get("target_url", ""),
            "summary": data.get("detail", ""),
            "evidence": ev,
        })
        break

    # ---- IDOR (individual findings with an ownership mismatch) ----
    idor_rows, auth_user = [], None
    for f in findings:
        ft = str(f.get("finding_type") or f.get("category") or "").lower()
        if ft != "idor":
            continue
        data = _d(f.get("data"))
        if not (data.get("ownership_mismatch") or data.get("unauthorized_access")):
            continue
        tgt = _d(data.get("target"))
        auth_user = data.get("authenticated_user_id", auth_user)
        idor_rows.append({
            "Resource": tgt.get("url") or data.get("url") or "—",
            "Object ID": data.get("object_id") or tgt.get("object_id") or "—",
            "Owner (User)": data.get("resource_owner_id", "—"),
            "Accessed as (User)": data.get("authenticated_user_id", "—"),
            "HTTP": data.get("status_code", "—"),
        })
    if idor_rows:
        items.append({
            "title": "IDOR — Unauthorized Cross-User Resource Access",
            "module": "IDOR",
            "category": "idor",
            "context": {"cross_user_access": True,
                        "multiple_records_exposed": len(idor_rows) > 1},
            "status": ("CONFIRMED", "status-confirmed"),
            "endpoint": "/rest/basket/{id}",
            "summary": (
                f"An authenticated user (ID {auth_user}) retrieved "
                f"{len(idor_rows)} resource(s) owned by other users."
            ),
            "evidence": [],
            "table": idor_rows,
        })

    # ---- XSS confirmed ----
    for t in xss_state.get("confirmed_vulnerabilities", []) or []:
        t = _d(t)
        if not t:
            continue
        items.append({
            "title": "Cross-Site Scripting — Confirmed Execution",
            "module": "XSS",
            "category": "xss",
            "context": {},
            "status": ("CONFIRMED", "status-confirmed"),
            "endpoint": t.get("url", ""),
            "summary": "Payload execution was observed (expected dialog triggered) during live testing.",
            "evidence": [
                ("Vector type", t.get("xss_target_type", "—")),
                ("Parameter", t.get("parameter") or "—"),
            ],
        })

    # ---- XSS potential (static DOM analysis, detection-only) ----
    for p in xss_state.get("potential_findings", []) or []:
        p = _d(p)
        if not p:
            continue
        ev_block = _d(p.get("evidence"))
        items.append({
            "title": p.get("vulnerability_type", "Potential DOM-based XSS"),
            "module": "XSS",
            "category": "xss",
            "context": {},
            "status": ("POTENTIAL", "status-potential"),
            "endpoint": p.get("endpoint", ""),
            "summary": p.get("detail", ""),
            "evidence": [
                ("Confirmation", p.get("confirmation",
                 "Not established by static analysis alone.")),
            ],
            "sources": p.get("sources") or ev_block.get("sources") or [],
            "sinks": p.get("sinks") or ev_block.get("sinks") or [],
        })

    # ---- XSS suspected ----
    for t in xss_state.get("successful_targets", []) or []:
        t = _d(t)
        if not t:
            continue
        items.append({
            "title": "Cross-Site Scripting — Suspected",
            "module": "XSS",
            "category": "xss",
            "context": {},
            "status": ("SUSPECTED", "status-suspected"),
            "endpoint": t.get("url", ""),
            "summary": "Reflected/stored behavior suggests XSS, but execution was not confirmed.",
            "evidence": [
                ("Vector type", t.get("xss_target_type", "—")),
                ("Parameter", t.get("parameter") or "—"),
            ],
        })

    # ---- Auth / Authorization (individual, evidence-backed findings) ----
    for f in findings:
        if not isinstance(f, dict):
            continue
        ft = str(f.get("finding_type") or f.get("category") or "").lower()
        data = _d(f.get("data"))
        is_authz = ft in ("auth", "authorization")
        vulnerable = f.get("vulnerable") or data.get("vulnerable")
        endpoint = f.get("endpoint") or _d(data.get("target")).get("url")
        if not (is_authz and vulnerable and endpoint):
            continue

        evidence_blob = _d(f.get("evidence")) or data
        enumeration = _d(evidence_blob.get("enumeration"))
        disclosed = (
            evidence_blob.get("disclosed_for")
            or enumeration.get("disclosed_for")
            or []
        )
        detail = f.get("detail") or data.get("detail", "")

        if disclosed:
            title = "Authentication — User Enumeration"
            ev = [("Accounts enumerated", ", ".join(map(str, disclosed)))]
        elif data.get("multiple_user_records_exposed"):
            title = "Authorization — Excessive Data Exposure"
            ev = [("Indicators", ", ".join(data.get("indicators", []) or []) or "—")]
        else:
            title = "Authorization / Authentication Weakness"
            ev = [("Indicators", ", ".join(data.get("indicators", []) or []) or "—")]

        items.append({
            "title": title,
            "module": "Authorization" if ft == "authorization" else "Authentication",
            "category": "authorization" if ft == "authorization" else "auth",
            "context": {
                "unauthenticated": bool(disclosed),
                "multiple_records_exposed": bool(data.get("multiple_user_records_exposed")),
            },
            "status": ("SUSPECTED", "status-suspected"),
            "endpoint": endpoint,
            "summary": detail,
            "evidence": ev,
        })

    # Compute each finding's severity from type + confidence + context, instead
    # of a hardcoded per-type label.
    for it in items:
        sev = compute_severity(
            it.get("category", ""),
            it.get("status", ("", ""))[0],
            it.get("context"),
        )
        it["sev"] = (sev["label"], sev["class"])
        it["sev_score"] = sev["score"]

    return items


def render_evidence_card(item):
    esc = html_module.escape
    sev_label, sev_cls = item["sev"]
    st_label, st_cls = item["status"]

    badge_cls = "badge-" + sev_cls.split("-")[1]
    score = item.get("sev_score")
    score_txt = f" · {score}" if score is not None else ""

    parts = [f'<div class="ev-card {sev_cls}">']
    parts.append('<div class="ev-head">')
    parts.append(f'<span class="status-chip {st_cls}">{esc(st_label)}</span>')
    parts.append(f'<span class="badge {badge_cls}">{esc(sev_label)}{esc(score_txt)}</span>')
    parts.append(f'<span class="ev-title">{esc(item["title"])}</span>')
    parts.append(f'<span class="ev-module">{esc(item["module"])}</span>')
    parts.append('</div>')

    if item.get("endpoint"):
        parts.append(f'<div class="ev-endpoint">{esc(str(item["endpoint"]))}</div>')
    if item.get("summary"):
        parts.append(f'<div class="ev-summary">{esc(str(item["summary"]))}</div>')

    rows = item.get("evidence") or []
    if rows:
        parts.append('<div class="ev-grid">')
        for k, v in rows:
            parts.append(f'<div class="ev-k">{esc(str(k))}</div><div class="ev-v">{esc(str(v))}</div>')
        parts.append('</div>')

    if item.get("sources") or item.get("sinks"):
        parts.append('<div style="margin-top:10px;">')
        for s in item.get("sources", []):
            parts.append(f'<span class="ev-chip src">source: {esc(str(s))}</span>')
        for s in item.get("sinks", []):
            parts.append(f'<span class="ev-chip snk">sink: {esc(str(s))}</span>')
        parts.append('</div>')

    parts.append('</div>')
    st.markdown("".join(parts), unsafe_allow_html=True)


# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("""
    <div style="margin-bottom: 12px;">
        <h2 style="margin: 0; font-size: 1.1rem; background: linear-gradient(90deg, #60A5FA, #A78BFA);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            Adaptive AI Agent
        </h2>
        <p style="margin: 2px 0 0; font-size: 0.75rem; color: #64748B;">
            Security Assessment Platform
        </p>
    </div>
    """, unsafe_allow_html=True)
    st.divider()
    st.markdown('<p style="font-size:0.75rem; font-weight:600; color:#94A3B8; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">Scan Control</p>', unsafe_allow_html=True)
    target_url = st.text_input(
        "Target URL",
        value="http://localhost:3000",
        label_visibility="collapsed",
        placeholder="http://localhost:3000"
    )
    start_scan = st.button(
        "Start New Scan",
        use_container_width=True,
        type="primary"
    )
    clear_results = st.button(
        "Clear Results",
        use_container_width=True
    )
    st.divider()
    st.markdown('<p style="font-size:0.75rem; font-weight:600; color:#94A3B8; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px;">System Status</p>', unsafe_allow_html=True)
    st.success("Agent Ready")
    st.markdown("""
    <div style="margin-top: 8px;">
        <div style="display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04);">
            <span style="font-size:0.75rem; color:#64748B;">AI Model</span>
            <span style="font-size:0.75rem; color:#E2E8F0; font-weight:500;">GPT-OSS 120B</span>
        </div>
        <div style="display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04);">
            <span style="font-size:0.75rem; color:#64748B;">Orchestration</span>
            <span style="font-size:0.75rem; color:#E2E8F0; font-weight:500;">LangGraph</span>
        </div>
        <div style="display:flex; justify-content:space-between; padding:6px 0;">
            <span style="font-size:0.75rem; color:#64748B;">Runtime</span>
            <span style="font-size:0.75rem; color:#E2E8F0; font-weight:500;">Groq</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# SESSION STATE
# ============================================================
if "result" not in st.session_state:
    st.session_state.result = None

if clear_results:
    st.session_state.result = None
    st.rerun()


# ============================================================
# SCAN EXECUTION
# ============================================================
if start_scan:
    with st.spinner("Adaptive AI Agent is performing the security assessment. This may take several minutes..."):
        try:
            result = run_agent(target_url)
            st.session_state.result = result
            st.success("Security assessment completed successfully.")
        except Exception as e:
            st.error(f"Assessment failed: {type(e).__name__}: {e}")


# ============================================================
# LANDING PAGE
# ============================================================
if st.session_state.result is None:
    st.markdown("""
    <div class="dash-header" style="text-align:center; padding:48px 36px;">
        <h1 style="font-size:2rem; margin-bottom:8px;">Adaptive AI Security Assessment</h1>
        <p class="subtitle" style="font-size:1rem;">AI-driven Multi-Step Web Application Penetration Testing</p>
    </div>
    """, unsafe_allow_html=True)

    st.info("Enter the target URL in the sidebar and click **Start New Scan** to begin the assessment.")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class="landing-card">
            <h3>Reconnaissance</h3>
            <p>Automated fingerprinting, crawling, and attack surface discovery</p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="landing-card">
            <h3>Vulnerability Assessment</h3>
            <p>SQLi, XSS, IDOR, authentication and authorization testing</p>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="landing-card">
            <h3>Adaptive AI Chaining</h3>
            <p>Dynamic module selection based on discovered findings</p>
        </div>
        """, unsafe_allow_html=True)
    st.stop()


# ============================================================
# RESULTS PAGE
# ============================================================
state = st.session_state.result

# -- Extract common data --
findings = state.get("findings", [])
modules = state.get("modules_run", [])
decision_log = state.get("decision_log", [])
decision_history = state.get("decision_history", [])
tech_stack = state.get("tech_stack", {})
if not tech_stack:
    tech_stack = state.get("recon_state", {}).get("tech_stack", {})
    if not tech_stack:
        for f in findings:
            if f.get("finding_type") in ("recon", "fingerprint", "crawl"):
                data = f.get("data", {})
                if isinstance(data, dict):
                    if "tech_stack" in data:
                        tech_stack.update(data["tech_stack"])
                    else:
                        tech_stack.update({k: v for k, v in data.items() if k in ["status_code", "server_header", "powered_by", "security_headers_present"]})
pages = state.get("pages", [])
metrics = state.get("metrics", {})
risk_assessments = state.get("risk_assessments", [])
recon_state = state.get("recon_state", {})
sqli_state = state.get("sqli_state", {})
xss_state = state.get("xss_state", {})
idor_state = state.get("idor_state", {})
authz_state = state.get("authz_state", {})
chain_history = state.get("chain_history", [])
step_count = state.get("step_count", 0)
target_display = state.get("target_url", target_url)

vulnerabilities = count_vulnerabilities(findings)
chains_triggered = metrics.get("chains_triggered", 0)
chains_completed = metrics.get("chains_completed", 0)


# ============================================================
# 1. PROFESSIONAL HEADER
# ============================================================
st.markdown(f"""
<div class="dash-header">
    <h1>Adaptive AI Security Assessment</h1>
    <p class="subtitle">AI-driven Multi-Step Web Application Penetration Testing</p>
    <div class="header-meta">
        <div class="header-meta-item">
            <span class="header-meta-label">Target</span>
            <span class="header-meta-value">{html_module.escape(str(target_display))}</span>
        </div>
        <div class="header-meta-item">
            <span class="header-meta-label">Status</span>
            <span class="header-meta-value" style="color:#34D399;">COMPLETED</span>
        </div>
        <div class="header-meta-item">
            <span class="header-meta-label">AI Model</span>
            <span class="header-meta-value">GPT-OSS 120B</span>
        </div>
        <div class="header-meta-item">
            <span class="header-meta-label">Orchestration</span>
            <span class="header-meta-value">LangGraph</span>
        </div>
        <div class="header-meta-item">
            <span class="header-meta-label">Runtime</span>
            <span class="header-meta-value">Groq</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ============================================================
# 2. ASSESSMENT SUMMARY
# ============================================================
st.markdown('<p class="sec-title">Assessment Summary</p><p class="sec-subtitle">Key metrics from the completed assessment</p>', unsafe_allow_html=True)

m1, m2, m3, m4, m5, m6, m7 = st.columns(7)
with m1:
    st.metric("Status", "Done")
with m2:
    st.metric("Modules", len(modules))
with m3:
    st.metric("Steps", step_count)
with m4:
    st.metric("Assessment Events", len(findings))
with m5:
    st.metric("Confirmed Findings", len(vulnerabilities))
with m6:
    st.metric("Chains", chains_triggered)
with m7:
    st.metric("Risk Categories", len(risk_assessments))

# AI-authored executive summary
exec_summary = state.get("executive_summary")
if exec_summary:
    st.markdown(
        '<p class="sec-title" style="margin-top:18px;">Executive Summary</p>'
        '<p class="sec-subtitle">AI-generated narrative of the assessment</p>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="dash-card" style="border-left:4px solid #8B5CF6;">'
        f'<div style="font-size:0.9rem; color:#CBD5E1; line-height:1.7;">'
        f'{html_module.escape(str(exec_summary))}</div></div>',
        unsafe_allow_html=True,
    )

st.divider()


# ============================================================
# 3. RISK OVERVIEW
# ============================================================
st.markdown('<p class="sec-title">Security Posture</p><p class="sec-subtitle">Risk categories identified during the assessment</p>', unsafe_allow_html=True)

if risk_assessments:
    # Build a set of confirmed vulnerability categories from findings
    confirmed_categories = set()
    for f in findings:
        if is_finding_vulnerable(f):
            ft = str(f.get("finding_type", "")).lower()
            confirmed_categories.add(ft)

    risk_html_parts = []
    for risk in risk_assessments:
        category = str(risk.get("category", "unknown")).lower()
        category_upper = category.upper()
        severity_label, severity_class = get_severity(category)
        impact = html_module.escape(str(risk.get("impact", "No impact information available.")))
        remediation = html_module.escape(str(risk.get("remediation", "No remediation available.")))

        if category in confirmed_categories:
            status_html = '<span class="badge badge-confirmed">Confirmed</span>'
        elif category in ("recon", "fingerprint", "crawl"):
            status_html = '<span class="badge badge-info">Informational</span>'
        else:
            status_html = '<span class="badge badge-pass">Pass</span>'

        risk_html_parts.append(f"""
        <div class="risk-card">
            <div class="risk-card-header">
                <span class="risk-card-title">{category_upper}</span>
                <div style="display:flex; gap:8px; align-items:center;">
                    <span class="badge {severity_class}">{severity_label}</span>
                    {status_html}
                </div>
            </div>
            <div class="risk-card-body">
                <strong>Impact:</strong> {impact}<br>
                <strong>Remediation:</strong> {remediation}
            </div>
        </div>
        """)

    st.markdown("".join(risk_html_parts), unsafe_allow_html=True)
else:
    st.info("No risk categories identified.")

st.divider()


# ============================================================
# 4. MODULE EXECUTION TIMELINE
# ============================================================
st.markdown('<p class="sec-title">Module Execution Timeline</p><p class="sec-subtitle">Ordered sequence of specialist modules executed by the AI orchestrator</p>', unsafe_allow_html=True)

# Determine which modules had findings
modules_with_findings = set()
for f in findings:
    if is_finding_vulnerable(f):
        ft = str(f.get("finding_type", "")).lower()
        mod = FINDING_TO_MODULE.get(ft, ft)
        modules_with_findings.add(mod)

# Determine chained modules
chained_modules = set()
for ch in chain_history:
    next_mod = ch.get("next_module", "")
    if next_mod:
        chained_modules.add(next_mod)

timeline_parts = []
for i, module in enumerate(modules, 1):
    display_name = MODULE_DISPLAY.get(module, module.replace("_", " ").title())
    purpose_short = MODULE_PURPOSE.get(module, "Security testing module").split(".")[0] + "."
    is_vuln = module in modules_with_findings
    is_chained = module in chained_modules

    if is_vuln and is_chained:
        dot_class = "timeline-dot-chain"
        status_class = "timeline-status-vuln"
        status_text = "Triggered adaptively &middot; Finding detected"
    elif is_vuln:
        dot_class = "timeline-dot-vuln"
        status_class = "timeline-status-vuln"
        status_text = "Finding detected"
    elif is_chained:
        dot_class = "timeline-dot-chain"
        status_class = "timeline-status-chain"
        status_text = "Triggered adaptively &middot; Completed"
    else:
        dot_class = "timeline-dot-ok"
        status_class = "timeline-status-ok"
        status_text = "Completed"

    timeline_parts.append(f'''<div class="timeline-item">'''
        f'''<div class="timeline-dot {dot_class}">{i:02d}</div>'''
        f'''<div class="timeline-title">{html_module.escape(display_name)}</div>'''
        f'''<div class="timeline-desc">{html_module.escape(purpose_short)}</div>'''
        f'''<div class="timeline-status {status_class}">{status_text}</div>'''
        f'''</div>''')

if timeline_parts:
    st.markdown(f'<div class="timeline-container">{"".join(timeline_parts)}</div>', unsafe_allow_html=True)
else:
    st.info("No modules have been executed.")

st.divider()


# ============================================================
# 5. DETAILED MODULE RESULTS
# ============================================================
st.markdown('<p class="sec-title">Detailed Module Results</p><p class="sec-subtitle">Findings and evidence from each specialist module</p>', unsafe_allow_html=True)

# -- RECON --
if "recon" in modules:
    with st.expander("Reconnaissance", expanded=False):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('recon', '')}")

        rc1, rc2, rc3, rc4 = st.columns(4)
        with rc1:
            st.metric("Targets Discovered", safe_get_list_len(recon_state, "discovered_targets"))
        with rc2:
            st.metric("Targets Tested", safe_get_list_len(recon_state, "tested_targets"))
        with rc3:
            st.metric("Endpoints", safe_get_list_len(recon_state, "endpoints"))
        with rc4:
            completed = recon_state.get("completed", False)
            st.metric("Status", "Completed" if completed else "Partial")

        st.markdown("**Result:** <span class='badge badge-info'>INFORMATIONAL</span>", unsafe_allow_html=True)
        st.caption("Reconnaissance is informational and does not represent a vulnerability finding.")

# -- AUTH --
if "auth" in modules:
    with st.expander("Authentication", expanded=False):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('auth', '')}")

        auth_findings = [f for f in findings if f.get("finding_type") == "auth"]
        auth_has_vuln = any(is_finding_vulnerable(f) for f in auth_findings)

        # Check if authenticated session was obtained
        session_available = bool(
            state.get("authenticated_session")
            or sqli_state.get("authenticated_session")
            or idor_state.get("authenticated_session")
        )

        if auth_has_vuln:
            st.markdown("**Result:** <span class='badge badge-confirmed'>FINDINGS DETECTED</span>", unsafe_allow_html=True)
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)

        if session_available:
            st.success("Authenticated session available for follow-up testing.")

        for af in auth_findings:
            data = af.get("data", {})
            if isinstance(data, dict):
                discovered = data.get("targets_discovered", safe_get_list_len(data, "discovered_targets"))
                tested = data.get("targets_tested", safe_get_list_len(data, "tested_targets"))
                if discovered:
                    st.caption(f"Targets discovered: {discovered}")
                if tested:
                    st.caption(f"Targets tested: {tested}")
                break # Only show once

# -- SQLi --
if "sqli_check" in modules:
    with st.expander("SQL Injection", expanded=True):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('sqli_check', '')}")

        sc1, sc2, sc3 = st.columns(3)
        with sc1:
            st.metric("Targets Discovered", safe_get_list_len(sqli_state, "discovered_targets"))
        with sc2:
            st.metric("Targets Tested", safe_get_list_len(sqli_state, "tested_targets"))
        with sc3:
            st.metric("Successful", safe_get_list_len(sqli_state, "successful_targets"))

        sqli_findings = [f for f in findings if f.get("finding_type") == "sqli"]
        sqli_vuln = any(is_finding_vulnerable(f) for f in sqli_findings)

        if sqli_vuln:
            st.markdown("**Result:** <span class='badge badge-critical'>VULNERABLE</span>", unsafe_allow_html=True)
            st.warning("SQL injection behavior was detected. Crafted input may enable unauthorized database access or authentication bypass.")
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)

        # Check for chain trigger
        sqli_chain = any(
            ch.get("source") == "sqli_check" for ch in chain_history
        ) or chains_triggered > 0

        if sqli_chain:
            st.info("Adaptive chain triggered: SQL injection produced an authenticated session, enabling follow-up IDOR testing.")

# -- IDOR --
if "idor_check" in modules:
    with st.expander("IDOR (Insecure Direct Object Reference)", expanded=True):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('idor_check', '')}")

        ic1, ic2, ic3 = st.columns(3)
        with ic1:
            st.metric("Targets Tested", safe_get_list_len(idor_state, "tested_targets"))
        with ic2:
            st.metric("Confirmed", safe_get_list_len(idor_state, "successful_targets"))
        with ic3:
            idor_completed = idor_state.get("completed", False)
            st.metric("Status", "Completed" if idor_completed else "Partial")

        idor_findings = [f for f in findings if f.get("finding_type") == "idor"]
        idor_vuln = any(is_finding_vulnerable(f) for f in idor_findings)

        if idor_vuln:
            st.markdown("**Result:** <span class='badge badge-high'>VULNERABLE</span>", unsafe_allow_html=True)
            st.warning("The authenticated user accessed resources owned by other users, confirming an authorization boundary violation.")
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)

        # Show IDOR evidence table
        for f in idor_findings:
            data = f.get("data", {})
            if not isinstance(data, dict):
                continue

            auth_user = data.get("authenticated_user_id", "Unknown")
            unauth_baskets = data.get("unauthorized_baskets", [])
            unauth_ids = data.get("unauthorized_basket_ids", [])
            if not unauth_ids:
                unauth_ids = data.get("accessible_basket_ids", [])

            if auth_user and auth_user != "Unknown":
                st.caption(f"Authenticated as User: {auth_user}")

            if unauth_baskets:
                table_data = []
                for b in unauth_baskets:
                    if isinstance(b, dict):
                        table_data.append({
                            "Resource": f"Basket {b.get('basket_id', 'N/A')}",
                            "Owner": f"User {b.get('owner_user_id', 'Unknown')}" if b.get("owner_user_id") is not None else "Unknown",
                            "Access": "UNAUTHORIZED"
                        })
                if table_data:
                    st.table(table_data)
            elif unauth_ids:
                st.caption(f"Unauthorized resources accessed: {len(unauth_ids)}")

            detail = data.get("detail")
            if detail and isinstance(detail, str):
                st.caption(detail)

# -- XSS --
if "xss_check" in modules:
    with st.expander("Cross-Site Scripting (XSS)", expanded=False):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('xss_check', '')}")

        # Distinct count kinds (never mixed): raw recon endpoints -> expanded
        # candidates -> candidates analyzed -> endpoints still unclassified.
        xc1, xc2, xc3, xc4 = st.columns(4)
        with xc1:
            st.metric("Raw Endpoints", safe_get_list_len(xss_state, "recon_targets"))
        with xc2:
            st.metric("XSS Candidates", safe_get_list_len(xss_state, "candidate_pool"))
        with xc3:
            st.metric("Analyzed", safe_get_list_len(xss_state, "tested_targets"))
        with xc4:
            st.metric("Unclassified", safe_get_list_len(xss_state, "unclassified_targets"))

        xd1, xd2, xd3 = st.columns(3)
        with xd1:
            st.metric("Potential (unverified)", safe_get_list_len(xss_state, "potential_findings"))
        with xd2:
            st.metric("Suspected", safe_get_list_len(xss_state, "successful_targets"))
        with xd3:
            st.metric("Confirmed", safe_get_list_len(xss_state, "confirmed_vulnerabilities"))

        xss_findings = [f for f in findings if f.get("finding_type") == "xss"]
        xss_vuln = any(is_finding_vulnerable(f) for f in xss_findings)
        potential = (
            xss_state.get("potential_findings", [])
            if isinstance(xss_state, dict)
            else []
        )

        if xss_vuln:
            st.markdown("**Result:** <span class='badge badge-medium'>FINDINGS DETECTED</span>", unsafe_allow_html=True)
            st.warning("Confirmed cross-site scripting behavior was detected in one or more endpoints.")
        elif potential:
            st.markdown("**Result:** <span class='badge badge-info'>POTENTIAL FINDINGS</span>", unsafe_allow_html=True)
            st.info("Potential XSS leads were detected by static analysis. These are unverified and require manual confirmation before being treated as vulnerabilities.")
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)
            st.caption("No confirmed XSS vulnerabilities were identified.")

        # Detection-only: show each potential finding's endpoint and evidence.
        if potential:
            table_data = []
            for p in potential:
                if not isinstance(p, dict):
                    continue
                evidence = p.get("evidence", {}) if isinstance(p.get("evidence"), dict) else {}
                sources = p.get("sources") or evidence.get("sources") or []
                sinks = p.get("sinks") or evidence.get("sinks") or []
                table_data.append({
                    "Endpoint": p.get("endpoint", ""),
                    "Type": p.get("vulnerability_type", "Potential DOM-based XSS"),
                    "Status": p.get("status", "potential"),
                    "Sources": ", ".join(sources) if isinstance(sources, list) else str(sources),
                    "Sinks": ", ".join(sinks) if isinstance(sinks, list) else str(sinks),
                })
            if table_data:
                st.caption("Potential XSS findings (detection-only; not confirmed by static analysis):")
                st.table(table_data)

# -- AUTHORIZATION --
if "authorization" in modules:
    with st.expander("Authorization", expanded=False):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('authorization', '')}")

        az_tested = safe_get_list_len(authz_state, "tested_targets")
        az_suspected = safe_get_list_len(authz_state, "successful_targets")
        az_confirmed = safe_get_list_len(authz_state, "confirmed_vulnerabilities")

        az1, az2, az3 = st.columns(3)
        with az1:
            st.metric("Targets Tested", az_tested)
        with az2:
            st.metric("Suspected BOLA", az_suspected)
        with az3:
            st.metric("Confirmed Bypass", az_confirmed)

        # Authorization findings live in the module state (they are
        # canonicalized to the "auth" category in the global findings list,
        # so filtering that list by category is unreliable).
        az_findings = (
            authz_state.get("findings")
            or authz_state.get("successful_targets")
            or []
        )

        if az_confirmed > 0:
            st.markdown("**Result:** <span class='badge badge-high'>VULNERABLE</span>", unsafe_allow_html=True)
            st.warning("Confirmed authorization bypass (broken object/function-level authorization) detected.")
        elif az_suspected > 0 or az_findings:
            st.markdown("**Result:** <span class='badge badge-medium'>FINDINGS DETECTED</span>", unsafe_allow_html=True)
            st.warning("Suspected authorization weakness / excessive data exposure detected (requires manual confirmation).")
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)
            st.success("No authorization findings were identified by this module.")

        # Surface the affected endpoints + evidence.
        if az_findings:
            rows = []
            for f in az_findings[:12]:
                if not isinstance(f, dict):
                    continue
                data = f.get("data") if isinstance(f.get("data"), dict) else f
                tgt = data.get("target") if isinstance(data.get("target"), dict) else {}
                url = tgt.get("url") or f.get("endpoint") or data.get("url") or "—"
                detail = f.get("detail") or data.get("detail") or ""
                rows.append({"Endpoint": url, "Observation": (detail[:140] if detail else "—")})
            if rows:
                st.table(rows)

        st.info(
            "Note: confirmed broken object-level authorization (BOLA/IDOR) on "
            "user baskets is reported under the IDOR module and the Adaptive AI "
            "Chain below."
        )

st.divider()


# ============================================================
# 6. ADAPTIVE AI CHAIN
# ============================================================
st.markdown('<p class="sec-title">Adaptive AI Chain</p><p class="sec-subtitle">Dynamic module chaining based on discovered findings</p>', unsafe_allow_html=True)

idor_ran = "idor_check" in modules
has_chain = chains_triggered > 0 or chains_completed > 0

if has_chain or idor_ran:
    # Determine chain details from chain_history or pending_chains
    chain_source = "SQL Injection"
    chain_trigger = "Authenticated session obtained"
    chain_target = "IDOR"
    chain_outcome = "Unauthorized resource access confirmed"

    for ch in chain_history:
        if ch.get("type") == "sqli_to_idor":
            chain_source = "SQL Injection"
            chain_target = "IDOR"

    st.markdown(f"""
    <div class="chain-flow">
        <div class="chain-node node-red">
            <h4>{chain_source}</h4>
            <p>Injection testing</p>
        </div>
        <span class="chain-arrow">→</span>
        <div class="chain-node node-blue">
            <h4>{chain_trigger}</h4>
            <p>Valid session produced</p>
        </div>
        <span class="chain-arrow">→</span>
        <div class="chain-node node-purple">
            <h4>AI Decision</h4>
            <p>Follow-up module selected</p>
        </div>
        <span class="chain-arrow">→</span>
        <div class="chain-node node-amber">
            <h4>{chain_target} Testing</h4>
            <p>Cross-user access testing</p>
        </div>
        <span class="chain-arrow">→</span>
        <div class="chain-node node-green">
            <h4>{chain_outcome}</h4>
            <p>Authorization violation confirmed</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="dash-card" style="margin-top:12px;">
        <div style="font-size:0.95rem; font-weight:600; color:#F8FAFC; margin-bottom:8px;">How Adaptive Chaining Works</div>
        <div style="font-size:0.85rem; color:#94A3B8; line-height:1.7;">
            The agent does not follow a fixed vulnerability-testing sequence. It uses information discovered during
            execution to determine whether a follow-up module is relevant.<br><br>
            <strong style="color:#CBD5E1;">Trigger:</strong> SQL injection testing produced an authenticated session.<br>
            <strong style="color:#CBD5E1;">Decision:</strong> IDOR became relevant because authenticated access was available.<br>
            <strong style="color:#CBD5E1;">Outcome:</strong> IDOR testing confirmed unauthorized cross-user resource access.
        </div>
    </div>
    """, unsafe_allow_html=True)
else:
    st.info("No adaptive chain was triggered during this assessment.")

st.divider()


# ============================================================
# 7. RECONNAISSANCE RESULTS
# ============================================================
st.markdown('<p class="sec-title">Reconnaissance</p><p class="sec-subtitle">Application attack surface and technology profile</p>', unsafe_allow_html=True)

recon_tab1, recon_tab2, recon_tab3 = st.tabs(["Technology & Headers", "Attack Surface", "Discovered Endpoints"])

with recon_tab1:
    t1, t2 = st.columns(2)
    with t1:
        st.markdown("##### Technology Stack")
        if tech_stack:
            st.markdown(f"**HTTP Status:** `{tech_stack.get('status_code', 'N/A')}`")
            st.markdown(f"**Server:** `{tech_stack.get('server_header', 'N/A')}`")
            st.markdown(f"**Powered By:** `{tech_stack.get('powered_by', 'N/A')}`")
        else:
            st.caption("No technology information available.")

    with t2:
        st.markdown("##### Security Headers")
        headers = tech_stack.get("security_headers_present", {})
        if headers:
            for header, present in headers.items():
                if present:
                    st.success(f"Present: {header}")
                else:
                    st.error(f"Missing: {header}")
        else:
            st.caption("No security header information available.")

    unusual_headers = tech_stack.get("unusual_headers", [])
    if unusual_headers:
        with st.expander("Unusual / Leaked Headers"):
            for h in unusual_headers:
                st.text(h)

with recon_tab2:
    attack_surface = recon_state.get("attack_surface", {})
    if attack_surface and isinstance(attack_surface, dict):
        categories = [
            ("Authentication", "authentication"),
            ("Authorization", "authorization"),
            ("User Data", "user_data"),
            ("Transactions", "transactions"),
            ("Injection", "injection"),
            ("Client Side", "client_side"),
            ("Other", "other"),
        ]

        # Show counts
        as_cols = st.columns(len(categories))
        for col, (label, key) in zip(as_cols, categories):
            targets = attack_surface.get(key, [])
            count = len(targets) if isinstance(targets, list) else 0
            with col:
                st.metric(label, count)

        # Detail expanders
        for label, key in categories:
            targets = attack_surface.get(key, [])
            if isinstance(targets, list) and targets:
                with st.expander(f"{label} Endpoints ({len(targets)})"):
                    for t in targets:
                        if isinstance(t, dict):
                            url = t.get("url", t.get("endpoint", "N/A"))
                            method = t.get("method", "")
                            st.text(f"{method} {url}" if method else str(url))
                        else:
                            st.text(str(t))
    else:
        st.caption("No attack surface data available.")

with recon_tab3:
    # Show key endpoint categories
    ep_categories = [
        ("Auth Endpoints", "auth_endpoints"),
        ("User Endpoints", "user_endpoints"),
        ("Transaction Endpoints", "transaction_endpoints"),
        ("API Endpoints", "api_endpoints"),
        ("Page Endpoints", "page_endpoints"),
    ]

    for label, key in ep_categories:
        endpoints = recon_state.get(key, [])
        if isinstance(endpoints, list) and endpoints:
            with st.expander(f"{label} ({len(endpoints)})"):
                for ep in endpoints:
                    if isinstance(ep, dict):
                        st.text(ep.get("url", ep.get("endpoint", str(ep))))
                    else:
                        st.text(str(ep))

    # Discovered pages
    if pages:
        with st.expander(f"Discovered Pages ({len(pages)})"):
            for page in pages:
                st.text(page)

st.divider()


# ============================================================
# 8. RISK & IMPACT ANALYSIS
# ============================================================
st.markdown('<p class="sec-title">Risk &amp; Impact Analysis</p><p class="sec-subtitle">Detailed risk assessment with remediation guidance</p>', unsafe_allow_html=True)

if risk_assessments:
    for risk in risk_assessments:
        category = str(risk.get("category", "unknown")).lower()
        category_upper = category.upper()
        severity_label, severity_class = get_severity(category)
        impact = risk.get("impact", "No impact information available.")
        remediation = risk.get("remediation", "No remediation available.")

        is_confirmed = category in confirmed_categories if 'confirmed_categories' in dir() else False

        with st.expander(f"{category_upper}  —  {severity_label}"):
            if is_confirmed:
                st.markdown(f"<span class='badge {severity_class}'>{severity_label}</span> <span class='badge badge-confirmed'>Confirmed</span>", unsafe_allow_html=True)
            elif category in ("recon", "fingerprint", "crawl"):
                st.markdown(f"<span class='badge badge-info'>Informational</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"<span class='badge badge-pass'>Pass</span>", unsafe_allow_html=True)

            st.markdown(f"**Impact:** {impact}")
            st.markdown(f"**Recommended Remediation:** {remediation}")
else:
    st.info("No risk analysis available.")

st.divider()


# ============================================================
# 9. BASELINE VS ADAPTIVE COMPARISON
# ============================================================
st.markdown('<p class="sec-title">Baseline vs Adaptive Agent</p><p class="sec-subtitle">Comparison of assessment behavior with and without adaptive chaining</p>', unsafe_allow_html=True)

# Calculate baseline estimates
idor_was_chained = any(
    ch.get("next_module") == "idor_check"
    for ch in chain_history
)

idor_finding_count = len([
    f for f in findings
    if f.get("finding_type") in ("idor", "idor_check")
])
idor_vuln_count = len([
    f for f in vulnerabilities
    if f.get("finding_type") in ("idor", "idor_check")
])

if idor_was_chained:
    b_modules = max(0, len(modules) - 1)
    b_steps = max(0, step_count - 1)
    b_findings = max(0, len(findings) - idor_finding_count)
    b_vulns = max(0, len(vulnerabilities) - idor_vuln_count)
    b_idor = "No"
else:
    b_modules = len(modules)
    b_steps = step_count
    b_findings = len(findings)
    b_vulns = len(vulnerabilities)
    b_idor = "Yes" if idor_ran else "No"

bva_html = f"""
<div class="bva-container">
    <div class="bva-card baseline">
        <div class="bva-header-row">
            <div class="bva-title-col">
                <div class="bva-icon-box">BL</div>
                <div>
                    <h3 class="bva-title">BASELINE</h3>
                    <p class="bva-subtitle">Chaining Disabled</p>
                </div>
            </div>
            <div class="bva-badge">Linear</div>
        </div>
        <div class="bva-metric">
            <span>Modules Executed</span>
            <span class="bva-metric-val">{b_modules}</span>
        </div>
        <div class="bva-metric">
            <span>Total Steps</span>
            <span class="bva-metric-val">{b_steps}</span>
        </div>
        <div class="bva-metric">
            <span>Total Findings</span>
            <span class="bva-metric-val">{b_findings}</span>
        </div>
        <div class="bva-metric">
            <span>Vulnerabilities</span>
            <span class="bva-metric-val val-amber">{b_vulns}</span>
        </div>
        <div class="bva-metric">
            <span>IDOR Executed</span>
            <span class="bva-metric-val val-red">{b_idor}</span>
        </div>
        <div class="bva-msg-box">
            Baseline execution follows a fixed assessment path. IDOR is not automatically triggered without adaptive chaining.
        </div>
    </div>
    <div class="bva-card adaptive">
        <div class="bva-header-row">
            <div class="bva-title-col">
                <div class="bva-icon-box">AD</div>
                <div>
                    <h3 class="bva-title">ADAPTIVE AGENT</h3>
                    <p class="bva-subtitle">Chaining Enabled</p>
                </div>
            </div>
            <div class="bva-badge">Adaptive</div>
        </div>
        <div class="bva-metric">
            <span>Modules Executed</span>
            <span class="bva-metric-val">{len(modules)}</span>
        </div>
        <div class="bva-metric">
            <span>Total Steps</span>
            <span class="bva-metric-val">{step_count}</span>
        </div>
        <div class="bva-metric">
            <span>Total Findings</span>
            <span class="bva-metric-val">{len(findings)}</span>
        </div>
        <div class="bva-metric">
            <span>Vulnerabilities</span>
            <span class="bva-metric-val val-amber">{len(vulnerabilities)}</span>
        </div>
        <div class="bva-metric">
            <span>IDOR Executed</span>
            <span class="bva-metric-val val-green">{"Yes" if idor_ran else "No"}</span>
        </div>
        <div class="bva-msg-box">
            Adaptive execution recognized that SQL injection produced an authenticated session and automatically expanded the assessment to include IDOR testing.
        </div>
    </div>
</div>
"""
st.markdown(bva_html, unsafe_allow_html=True)

if idor_was_chained:
    st.markdown("""
    <div class="dash-card">
        <div style="font-size:0.9rem; font-weight:600; color:#34D399; margin-bottom:6px;">Why Adaptive Wins</div>
        <div style="font-size:0.85rem; color:#94A3B8; line-height:1.6;">
            Baseline execution follows a fixed assessment path and would not test for IDOR vulnerabilities
            because it lacks the context to recognize when cross-user access testing is meaningful.<br><br>
            Adaptive execution recognized that SQL injection produced an authenticated session and
            automatically expanded the assessment to include IDOR, discovering unauthorized access
            to other users' resources.
        </div>
    </div>
    """, unsafe_allow_html=True)

st.divider()


# ============================================================
# 10. FINDINGS & EVIDENCE
# ============================================================
st.markdown('<p class="sec-title">Findings &amp; Evidence</p><p class="sec-subtitle">Every finding with its supporting evidence, ranked by severity (sensitive values redacted)</p>', unsafe_allow_html=True)

evidence_items = build_evidence_findings(state)

_sev_rank = {"sev-critical": 0, "sev-high": 1, "sev-medium": 2, "sev-low": 3, "sev-info": 4}
_status_rank = {"CONFIRMED": 0, "SUSPECTED": 1, "POTENTIAL": 2, "INFO": 3, "PASS": 4}
evidence_items.sort(
    key=lambda it: (_sev_rank.get(it["sev"][1], 9), _status_rank.get(it["status"][0], 9))
)

# Severity / status summary pills
pill_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "POTENTIAL": 0}
for it in evidence_items:
    if it["status"][0] == "POTENTIAL":
        pill_counts["POTENTIAL"] += 1
    else:
        pill_counts[it["sev"][0]] = pill_counts.get(it["sev"][0], 0) + 1

pill_html = ['<div class="sev-summary-row">']
for lbl, cls in [
    ("CRITICAL", "c-critical"), ("HIGH", "c-high"), ("MEDIUM", "c-medium"),
    ("LOW", "c-low"), ("POTENTIAL", "c-potential"),
]:
    pill_html.append(
        f'<div class="sev-pill {cls}"><div class="num">{pill_counts.get(lbl, 0)}</div>'
        f'<div class="lbl">{lbl}</div></div>'
    )
pill_html.append('</div>')
st.markdown("".join(pill_html), unsafe_allow_html=True)

if evidence_items:
    for it in evidence_items:
        render_evidence_card(it)
        if it.get("table"):
            st.table(it["table"])
else:
    st.markdown(
        '<div class="ev-empty">No confirmed vulnerabilities or potential findings were identified.</div>',
        unsafe_allow_html=True,
    )

with st.expander("Raw finding data (redacted JSON)"):
    if findings:
        st.json(redact_sensitive(copy.deepcopy(findings)))
    else:
        st.caption("No findings recorded.")
    st.markdown("**Reconnaissance state**")
    st.json(redact_sensitive(copy.deepcopy(recon_state)))
    if "xss_check" in modules:
        st.markdown("**XSS state**")
        st.json(redact_sensitive(copy.deepcopy(xss_state)))

st.divider()


# ============================================================
# 11. AI DECISION LOG
# ============================================================
st.markdown('<p class="sec-title">AI Decision Log</p><p class="sec-subtitle">Complete reasoning trail showing why each module was selected</p>', unsafe_allow_html=True)

with st.expander("Decision History", expanded=False):
    if decision_history:
        decision_parts = []
        for d in decision_history:
            step_num = d.get("step", "?")
            action = d.get("action", "unknown")
            reason = html_module.escape(str(d.get("reason", "")))
            display_action = MODULE_DISPLAY.get(action, action.replace("_", " ").title())

            # Check if this is a chain-related decision
            is_chain_step = action == "idor_check" and idor_was_chained

            if is_chain_step:
                decision_parts.append(f"""
                <div class="decision-step" style="border-left: 3px solid rgba(139,92,246,0.4);">
                    <div class="decision-step-num" style="color:#A78BFA;">Chain Event &middot; Step {step_num}</div>
                    <div class="decision-step-action">{html_module.escape(display_action)}</div>
                    <div class="decision-step-reason">{reason}</div>
                </div>
                """)
            else:
                decision_parts.append(f"""
                <div class="decision-step">
                    <div class="decision-step-num">Step {step_num}</div>
                    <div class="decision-step-action">{html_module.escape(display_action)}</div>
                    <div class="decision-step-reason">{reason}</div>
                </div>
                """)

        st.markdown("".join(decision_parts), unsafe_allow_html=True)

    elif decision_log:
        for entry in decision_log:
            st.text(entry)
    else:
        st.caption("No decision log available.")

st.divider()


# ============================================================
# 12. SECURITY ASSESSMENT REPORT
# ============================================================
st.markdown('<p class="sec-title">Security Assessment Report</p><p class="sec-subtitle">Downloadable report summarizing the complete assessment</p>', unsafe_allow_html=True)

with st.expander("View & Download Report", expanded=False):
    try:
        lines = []
        lines.append("=" * 70)
        lines.append("ADAPTIVE AI SECURITY ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Target:                {target_display}")
        lines.append(f"Assessment Status:     COMPLETED")
        lines.append(f"AI Model:              GPT-OSS 120B")
        lines.append(f"Orchestration:         LangGraph")
        lines.append(f"Runtime:               Groq")
        lines.append(f"Assessment Start:      {state.get('assessment_start_time', 'N/A')}")
        lines.append("")

        # AI-authored narrative
        _exec = state.get("executive_summary")
        if _exec:
            lines.append("NARRATIVE (AI-GENERATED)")
            lines.append("-" * 40)
            import textwrap as _tw
            for _ln in _tw.wrap(str(_exec), width=78):
                lines.append(_ln)
            lines.append("")

        # Metrics
        lines.append("ASSESSMENT METRICS")
        lines.append("-" * 40)
        lines.append(f"Modules Executed:      {len(modules)}")
        lines.append(f"Workflow Steps:        {step_count}")
        lines.append(f"Total Findings:        {len(findings)}")
        lines.append(f"Confirmed Vulns:       {len(vulnerabilities)}")
        lines.append(f"Adaptive Chains:       {chains_triggered}")
        lines.append(f"Chains Completed:      {chains_completed}")
        lines.append(f"Risk Categories:       {len(risk_assessments)}")
        lines.append("")

        # Modules
        lines.append("MODULES EXECUTED")
        lines.append("-" * 40)
        for i, mod in enumerate(modules, 1):
            display = MODULE_DISPLAY.get(mod, mod)
            lines.append(f"  {i}. {display}")
        lines.append("")

        # Findings Summary
        lines.append("FINDINGS SUMMARY")
        lines.append("-" * 40)
        from collections import Counter
        if not findings:
            lines.append("  No findings recorded.")
        else:
            counts = Counter()
            for f in findings:
                ftype = MODULE_DISPLAY.get(f.get("finding_type", ""), f.get("finding_type", "unknown").upper())
                counts[ftype] += 1
            for ftype, count in counts.items():
                lines.append(f"  {ftype.ljust(20)} {count}")
            lines.append("  " + "─" * 22)
            lines.append(f"  Total".ljust(22) + f" {len(findings)}")
        lines.append("")

        # Confirmed Vulnerabilities
        lines.append("CONFIRMED VULNERABILITIES")
        lines.append("-" * 40)
        if not vulnerabilities:
            lines.append("  No confirmed vulnerabilities.")
        else:
            vuln_counts = Counter()
            for v in vulnerabilities:
                vtype = MODULE_DISPLAY.get(v.get("finding_type", ""), v.get("finding_type", "unknown").upper())
                vuln_counts[vtype] += 1
            for vtype, count in vuln_counts.items():
                lines.append(f"  {vtype.ljust(20)} {count}")
            lines.append("  " + "─" * 22)
            lines.append(f"  Total".ljust(22) + f" {len(vulnerabilities)}")
        lines.append("")

        # Adaptive Chain
        lines.append("ADAPTIVE CHAIN")
        lines.append("-" * 40)
        if has_chain:
            lines.append("  Chain Detected: SQLi -> IDOR")
            lines.append("  Trigger: SQL injection produced an authenticated session.")
            lines.append("  Outcome: IDOR testing confirmed unauthorized cross-user resource access.")
        else:
            lines.append("  No adaptive chain was triggered.")
        lines.append("")

        # Risk Assessment
        lines.append("RISK ASSESSMENT")
        lines.append("-" * 40)
        if risk_assessments:
            for risk in risk_assessments:
                cat = risk.get("category", "unknown").upper()
                sev, _ = get_severity(risk.get("category", ""))
                lines.append(f"  [{cat}] Severity: {sev}")
                lines.append(f"    Impact: {risk.get('impact', 'N/A')}")
                lines.append(f"    Remediation: {risk.get('remediation', 'N/A')}")
                lines.append("")
        else:
            lines.append("  No risk assessment available.")
        lines.append("")

        # Remediation Summary
        lines.append("REMEDIATION SUMMARY")
        lines.append("-" * 40)
        if risk_assessments:
            for risk in risk_assessments:
                cat = risk.get("category", "unknown").upper()
                rem = risk.get("remediation", "N/A")
                lines.append(f"  [{cat}] {rem}")
        else:
            lines.append("  No remediation actions required.")
        lines.append("")

        # AI Decision Trail
        lines.append("AI DECISION TRAIL")
        lines.append("-" * 40)
        if decision_history:
            for d in decision_history:
                step_num = d.get("step", "?")
                action = MODULE_DISPLAY.get(d.get("action", ""), d.get("action", ""))
                reason = d.get("reason", "")
                lines.append(f"  Step {step_num}: {action}")
                lines.append(f"    Reason: {reason}")
        elif decision_log:
            for entry in decision_log:
                lines.append(f"  {entry}")
        else:
            lines.append("  No decision trail available.")
        lines.append("")
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        lines.append("=" * 70)

        report_str = "\n".join(lines)

        # Display report via UI components instead of plain text block
        st.markdown("### Executive Summary")
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Assessment Events", len(findings))
        r2.metric("Confirmed Findings", len(vulnerabilities))
        r3.metric("Adaptive Chains", chains_triggered)
        r4.metric("Risk Categories", len(risk_assessments))

        st.markdown("### Confirmed Vulnerabilities")
        if not vulnerabilities:
            st.success("No confirmed vulnerabilities detected.")
        else:
            for vtype, count in vuln_counts.items():
                st.markdown(f"- **{vtype}**: {count}")

        st.markdown("### Remediation Summary")
        if risk_assessments:
            for risk in risk_assessments:
                cat = risk.get("category", "unknown").upper()
                sev, sev_class = get_severity(risk.get("category", ""))
                rem = risk.get("remediation", "N/A")
                st.markdown(f"**{cat}** <span class='badge {sev_class}'>{sev}</span><br>*{rem}*", unsafe_allow_html=True)
        else:
            st.info("No remediation actions required.")

        st.download_button(
            "Download Report",
            data=report_str,
            file_name="security_assessment_report.txt",
            mime="text/plain",
            use_container_width=True
        )
    except Exception as e:
        st.error(f"Unable to generate report: {e}")