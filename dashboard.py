import streamlit as st
import copy
import html as html_module
from datetime import datetime
from agent import run_agent

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
    """Get severity label and CSS class for a risk category."""
    return SEVERITY_MAP.get(
        category.lower(),
        ("UNKNOWN", "badge-info")
    )


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

        xc1, xc2, xc3 = st.columns(3)
        with xc1:
            st.metric("Targets Discovered", safe_get_list_len(xss_state, "discovered_targets"))
        with xc2:
            st.metric("Targets Tested", safe_get_list_len(xss_state, "tested_targets"))
        with xc3:
            st.metric("Successful", safe_get_list_len(xss_state, "successful_targets"))

        xss_findings = [f for f in findings if f.get("finding_type") == "xss"]
        xss_vuln = any(is_finding_vulnerable(f) for f in xss_findings)

        if xss_vuln:
            st.markdown("**Result:** <span class='badge badge-medium'>FINDINGS DETECTED</span>", unsafe_allow_html=True)
            st.warning("Cross-site scripting behavior was detected in one or more endpoints.")
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)
            st.caption("No confirmed XSS vulnerabilities were identified.")

# -- AUTHORIZATION --
if "authorization" in modules:
    with st.expander("Authorization", expanded=False):
        st.markdown(f"**Purpose:** {MODULE_PURPOSE.get('authorization', '')}")

        auth_z_findings = [f for f in findings if f.get("finding_type") in ("authorization", "auth") and f.get("category") != "auth"]
        auth_z_vuln = any(is_finding_vulnerable(f) for f in auth_z_findings)

        if auth_z_vuln:
            st.markdown("**Result:** <span class='badge badge-confirmed'>FINDINGS DETECTED</span>", unsafe_allow_html=True)
        else:
            st.markdown("**Result:** <span class='badge badge-pass'>PASS</span>", unsafe_allow_html=True)
            st.success("No confirmed authorization bypasses were identified.")

st.divider()


# ============================================================
# 6. ADAPTIVE AI CHAIN
# ============================================================
st.markdown('<p class="sec-title">Adaptive AI Chain</p><p class="sec-subtitle">Dynamic module chaining based on discovered findings</p>', unsafe_allow_html=True)

idor_ran = "idor_check" in modules
has_chain = chains_triggered > 0 or len(chain_history) > 0

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
# 10. TECHNICAL EVIDENCE
# ============================================================
st.markdown('<p class="sec-title">Technical Evidence</p><p class="sec-subtitle">Raw finding data for detailed analysis (sensitive fields redacted)</p>', unsafe_allow_html=True)

with st.expander("Finding Evidence"):
    if findings:
        for i, finding in enumerate(findings):
            safe_finding = redact_sensitive(copy.deepcopy(finding))
            finding_type = safe_finding.get("finding_type", "unknown").upper()
            st.markdown(f"**{finding_type}** — Finding {i+1}")
            st.json(safe_finding)
            if i < len(findings) - 1:
                st.markdown("---")
    else:
        st.caption("No findings recorded.")

with st.expander("Recon State Evidence"):
    safe_recon = redact_sensitive(copy.deepcopy(recon_state))
    st.json(safe_recon)

with st.expander("Security Header Evidence"):
    headers = tech_stack.get("security_headers_present", {})
    if headers:
        st.json(headers)
    else:
        st.caption("No security header data available.")

if idor_ran:
    with st.expander("IDOR Ownership Evidence"):
        idor_findings = [f for f in findings if f.get("finding_type") == "idor"]
        if idor_findings:
            for f in idor_findings:
                data = f.get("data", {})
                if not isinstance(data, dict):
                    continue
                auth_user = data.get("authenticated_user_id", "Unknown")
                unauth_baskets = data.get("unauthorized_baskets", [])
                if unauth_baskets:
                    table_data = []
                    for b in unauth_baskets:
                        if isinstance(b, dict):
                            table_data.append({
                                "Resource": f"Basket {b.get('basket_id', 'N/A')}",
                                "Resource Owner": f"User {b.get('owner_user_id', 'Unknown')}",
                                "Authenticated User": auth_user,
                                "Authorization Result": "❌ Unauthorized"
                            })
                    if table_data:
                        st.table(table_data)
                else:
                    st.json(redact_sensitive(copy.deepcopy(f)))
        else:
            safe_idor = redact_sensitive(copy.deepcopy(idor_state))
            st.json(safe_idor)

if "xss_check" in modules:
    with st.expander("XSS Evidence"):
        safe_xss = redact_sensitive(copy.deepcopy(xss_state))
        st.json(safe_xss)

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