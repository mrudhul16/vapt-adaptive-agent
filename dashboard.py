import streamlit as st
from agent import app
from state import initial_state
st.set_page_config(
    page_title="Adaptive AI Agent",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #0B0E14;
        color: #E2E8F0;
    }
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Outfit', sans-serif !important;
        font-weight: 600 !important;
        letter-spacing: -0.5px;
        color: #F8FAFC;
    }
    h1 {
        background: linear-gradient(90deg, #60A5FA, #A78BFA);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.3s ease;
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
        font-size: 2.5rem !important;
        background: linear-gradient(180deg, #FFFFFF 0%, #94A3B8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    [data-testid="stMetricLabel"] {
        font-weight: 500 !important;
        color: #64748B !important;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.75rem !important;
    }
    hr {
        border-color: rgba(255, 255, 255, 0.05) !important;
    }
    div[data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.4);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    #MainMenu {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)
st.title("Adaptive AI Agent")
st.caption("Multistep Web Application Penetration Testing")
st.divider()
# Sidebar
with st.sidebar:
    st.header("Adaptive AI Agent")
    st.caption("AI-powered multistep web application security assessment")
    st.subheader("Scan Control")
    target = st.text_input(
        "Target URL",
        value="http://localhost:3000"
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
    st.subheader("System Status")
    st.success("● Agent Ready")
    st.caption("AI Model: GPT-OSS 120B")
    st.caption("Framework: LangGraph")
    st.caption("Runtime: Groq")
# Session state
if "result" not in st.session_state:
    st.session_state.result = None
if clear_results:
    st.session_state.result = None
    st.rerun()
# Run scan
if start_scan:
    with st.spinner("Adaptive AI Agent is performing assessment..."):
        try:
            state = initial_state(
                target,
                chaining_enabled=True
            )
            result = app.invoke(state)
            st.session_state.result = result
            st.success("Security assessment completed.")
        except Exception as e:
            st.error(f"Scan failed: {e}")
# Waiting screen
if st.session_state.result is None:
    st.info(
        "Enter the target URL in the sidebar and click **Start New Scan**."
    )
    col1, col2, col3 = st.columns(3)
    with col1:
        st.subheader("Reconnaissance")
        st.write("Fingerprinting and web crawling")
    with col2:
        st.subheader("Assessment")
        st.write("Authentication and vulnerability checks")
    with col3:
        st.subheader("Adaptive AI")
        st.write("Dynamic module selection and chaining")
    st.stop()
# Result
state = st.session_state.result
findings = state.get("findings", [])
modules = state.get("modules_run", [])
decision_log = state.get("decision_log", [])
tech_stack = state.get("tech_stack", {})
pages = state.get("pages", [])
vulnerabilities = []
for finding in findings:
    data = finding.get("data", {})
    if isinstance(data, dict) and data.get("vulnerable") is True:
        vulnerabilities.append(finding)
# Top metrics
st.subheader("Assessment Overview")
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Modules Completed", len(modules))
with c2:
    st.metric("Total Steps", state.get("step_count", 0))
with c3:
    st.metric("Total Findings", len(findings))
with c4:
    st.metric("Confirmed Vulnerabilities", len(vulnerabilities))
st.caption(f"Target: `{state.get('target_url', 'N/A')}`")
st.divider()
# Main sections
left, middle, right = st.columns(3)
with left:
    st.subheader("Module Execution")
    module_names = {
        "fingerprint": "Fingerprinting",
        "crawl": "Web Crawling",
        "auth_check": "Authentication Check",
        "idor_check": "IDOR Check",
        "sqli_check": "SQL Injection Check",
        "xss_check": "XSS Check"
    }
    for i, module in enumerate(modules, 1):
        st.success(
            f"{i}. {module_names.get(module, module)}"
        )
with middle:
    st.subheader("Vulnerability Overview")
    if findings:
        for finding in findings:
            finding_type = finding.get("finding_type", "unknown")
            data = finding.get("data", {})
            vulnerable = (
                isinstance(data, dict)
                and data.get("vulnerable") is True
            )
            if finding_type == "auth":
                login_successful = data.get("login_successful")
                if login_successful:
                    st.success(f"[PASS] {finding_type.upper()}")
                else:
                    st.warning(f"[FAIL] {finding_type.upper()}")
                    status_code = data.get("status_code", "Unknown")
                    st.caption(f"Authentication failed — HTTP {status_code}")
            elif vulnerable:
                st.error(
                    f"[VULN] {finding_type.upper()}"
                )
                if finding_type == "idor":
                    auth_user = data.get("authenticated_user_id", "Unknown")
                    unauth_ids = data.get("unauthorized_basket_ids", [])
                    unauth_baskets = data.get("unauthorized_baskets", [])
                    if not unauth_ids and "accessible_basket_ids" in data:
                        unauth_ids = data.get("accessible_basket_ids", [])
                    st.write(f"Authenticated User: {auth_user}")
                    st.write(f"Unauthorized Baskets: {len(unauth_ids)}")
                    if unauth_baskets:
                        table_data = [
                            {
                                "Basket ID": b.get("basket_id"),
                                "Owner User": f"User {b.get('owner_user_id')}" if b.get("owner_user_id") is not None else "Unknown"
                            }
                            for b in unauth_baskets
                        ]
                        st.table(table_data)
                    else:
                        st.info("No unauthorized basket ownership confirmed.")
                    if isinstance(data, dict) and data.get("detail"):
                        st.caption(data["detail"])
                else:
                    if isinstance(data, dict) and data.get("detail"):
                        st.caption(data["detail"])
            else:
                st.success(
                    f"[PASS] {finding_type.upper()}"
                )
    else:
        st.info("No findings recorded.")
with right:
    st.subheader("AI Decision Trail")
    if decision_log:
        for entry in decision_log:
            if "CHAINED" in entry:
                st.info(f"[CHAIN] {entry}")
            else:
                st.write(f"• {entry}")
    else:
        st.info("No decision log available.")
st.divider()
# Reconnaissance
st.subheader("Reconnaissance Results")
r1, r2 = st.columns(2)
with r1:
    st.write("### Technology & Server")
    if tech_stack:
        st.write(
            "**HTTP Status:**",
            tech_stack.get("status_code", "N/A")
        )
        st.write(
            "**Server:**",
            tech_stack.get("server_header", "N/A")
        )
        st.write(
            "**Powered By:**",
            tech_stack.get("powered_by", "N/A")
        )
    else:
        st.info("No fingerprint data available.")
with r2:
    st.write("### Security Headers")
    headers = tech_stack.get(
        "security_headers_present",
        {}
    )
    if headers:
        for header, present in headers.items():
            if present:
                st.success(f"✓ {header}")
            else:
                st.error(f"✗ {header}")
    else:
        st.info("No security header information.")
# Unusual headers
unusual_headers = tech_stack.get("unusual_headers", [])
if unusual_headers:
    with st.expander("View Unusual / Leaked Headers"):
        for header in unusual_headers:
            st.text(header)
# Discovered pages
st.subheader("Discovered Pages & Resources")
crawl_finding = next(
    (
        f for f in findings
        if f.get("finding_type") == "crawl"
    ),
    None
)
if crawl_finding:
    discovered = crawl_finding.get(
        "data",
        {}
    ).get(
        "discovered_pages",
        []
    )
else:
    discovered = pages
if discovered:
    for page in discovered:
        st.text(page)
else:
    st.info("No pages/resources discovered.")
st.divider()
# Adaptive chain
st.subheader("Adaptive AI Chain")
idor_ran = "idor_check" in modules
if idor_ran:
    a, b, c = st.columns(3)
    with a:
        st.success("Authentication\n\nSession obtained")
    with b:
        st.info("TOKEN\n\nValid session")
    with c:
        st.warning("IDOR\n\nAutomatically Triggered")
    st.success(
        "The agent detected a valid session and automatically chained the IDOR module."
    )
else:
    st.info("No adaptive chain was triggered during this assessment.")
# Baseline comparison
st.divider()
st.markdown("""
<div style="margin-bottom: 24px;">
    <h2 style="margin: 0; display: flex; align-items: center; gap: 10px;">Baseline vs Adaptive Agent</h2>
    <p style="margin: 5px 0 0 0; color: #9ca3af; font-size: 15px;">Comparison of assessment behavior with and without adaptive chaining</p>
</div>
""".replace('\n', ''), unsafe_allow_html=True)
chained_logs = [entry for entry in decision_log if "CHAINED" in entry]
has_chain = len(chained_logs) > 0
idor_finding_count = len([f for f in findings if f.get("finding_type") in ("idor", "idor_check")])
idor_vuln_count = len([f for f in vulnerabilities if f.get("finding_type") in ("idor", "idor_check")])
b_modules = len(modules) - len(chained_logs)
b_steps = state.get("step_count", 0) - len(chained_logs)
b_findings = len(findings) - idor_finding_count
b_vulns = len(vulnerabilities) - idor_vuln_count
target = "IDOR"
cause = "Previous Check"
effect = "Trigger Condition"
clean_reason = "condition met"
chain_text = ""
if has_chain:
    chain_text = chained_logs[0]
    if "CHAINED into '" in chain_text:
        target = chain_text.split("CHAINED into '")[1].split("'")[0].replace("_check", "").upper()
    if "because: " in chain_text:
        clean_reason = chain_text.split("because: ")[1].split("—")[0].split("-")[0].strip()
        if " produced an " in clean_reason:
            parts = clean_reason.split(" produced an ")
            cause = parts[0].strip().title()
            effect = parts[1].strip().title()
        else:
            cause = clean_reason.title()
cards_css = """
<style>
.bva-container { display: flex; gap: 24px; margin-bottom: 30px; }
.bva-card { flex: 1; border-radius: 16px; padding: 24px; background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(12px); display: flex; flex-direction: column; transition: transform 0.3s ease, box-shadow 0.3s ease; }
.bva-card:hover { transform: translateY(-2px); }
.bva-card.baseline { border: 1px solid rgba(59, 130, 246, 0.2); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255,255,255,0.05); }
.bva-card.baseline:hover { box-shadow: 0 8px 32px rgba(59, 130, 246, 0.15), inset 0 1px 0 rgba(255,255,255,0.05); }
.bva-card.adaptive { border: 1px solid rgba(16, 185, 129, 0.2); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255,255,255,0.05); }
.bva-card.adaptive:hover { box-shadow: 0 8px 32px rgba(16, 185, 129, 0.15), inset 0 1px 0 rgba(255,255,255,0.05); }
.bva-header-row { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; }
.bva-title-col { display: flex; gap: 16px; align-items: center; }
.bva-icon-box { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 700; font-family: 'Outfit', sans-serif; letter-spacing: 1px; }
.baseline .bva-icon-box { background: linear-gradient(135deg, rgba(59, 130, 246, 0.2) 0%, rgba(37, 99, 235, 0.1) 100%); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.3); }
.adaptive .bva-icon-box { background: linear-gradient(135deg, rgba(16, 185, 129, 0.2) 0%, rgba(5, 150, 105, 0.1) 100%); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.3); }
.bva-title { font-size: 1.1rem; font-weight: 600; margin: 0; color: #F8FAFC; letter-spacing: 0.5px; }
.bva-subtitle { font-size: 0.8rem; margin: 4px 0 0 0; color: #94A3B8; text-transform: uppercase; letter-spacing: 1px; }
.adaptive .bva-subtitle { color: #34D399; }
.bva-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
.baseline .bva-badge { background: rgba(59, 130, 246, 0.1); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.2); }
.adaptive .bva-badge { background: rgba(16, 185, 129, 0.1); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.2); }
.bva-metric { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.9rem; color: #CBD5E1; }
.bva-metric:last-of-type { border-bottom: none; }
.bva-metric-label { display: flex; align-items: center; gap: 8px; font-weight: 400; }
.bva-metric-val { font-weight: 600; font-size: 1rem; }
.baseline .bva-metric-val { color: #F8FAFC; }
.adaptive .bva-metric-val { color: #F8FAFC; }
.bva-metric-val.val-red { color: #F87171 !important; text-shadow: 0 0 10px rgba(248, 113, 113, 0.3); }
.bva-metric-val.val-yellow { color: #FBBF24 !important; text-shadow: 0 0 10px rgba(251, 191, 36, 0.3); }
.bva-msg-box { margin-top: 20px; padding: 14px 16px; border-radius: 8px; display: flex; gap: 10px; align-items: flex-start; font-size: 0.85rem; line-height: 1.5; font-weight: 400; }
.baseline .bva-msg-box { background: rgba(59, 130, 246, 0.05); border-left: 3px solid #3B82F6; color: #94A3B8; }
.adaptive .bva-msg-box { background: rgba(16, 185, 129, 0.05); border-left: 3px solid #10B981; color: #94A3B8; }
</style>
"""
cards_html = f"""
{cards_css}
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
            <div class="bva-badge">Linear Execution</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Modules Executed</div>
            <div class="bva-metric-val">{b_modules}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Total Steps</div>
            <div class="bva-metric-val">{b_steps}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Total Findings</div>
            <div class="bva-metric-val">{b_findings}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Vulnerabilities Confirmed</div>
            <div class="bva-metric-val val-yellow">{b_vulns}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">IDOR Executed</div>
            <div class="bva-metric-val val-red">No</div>
        </div>
        <div class="bva-msg-box">
            <div>Runs core modules only. {target if has_chain else 'IDOR'} is not automatically triggered.</div>
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
            <div class="bva-badge">Adaptive Execution</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Modules Executed</div>
            <div class="bva-metric-val">{len(modules)}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Total Steps</div>
            <div class="bva-metric-val">{state.get('step_count', 0)}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Total Findings</div>
            <div class="bva-metric-val">{len(findings)}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">Vulnerabilities Confirmed</div>
            <div class="bva-metric-val val-yellow">{len(vulnerabilities)}</div>
        </div>
        <div class="bva-metric">
            <div class="bva-metric-label">IDOR Executed</div>
            <div class="bva-metric-val">{'Yes' if idor_ran else 'No'}</div>
        </div>
        <div class="bva-msg-box">
            <div>Dynamically chains to {target if has_chain else 'IDOR'} after {clean_reason.lower() if has_chain else 'trigger condition is met'}.</div>
        </div>
    </div>
</div>
"""
st.markdown(cards_html.replace('\n', ''), unsafe_allow_html=True)
if has_chain:
    target_disp = f"{target} Check" if "Check" not in target else target
    chain_css = """
    <style>
    .chain-container { display: flex; align-items: center; justify-content: space-between; margin-top: 16px; margin-bottom: 32px; position: relative; }
    .chain-container::before { content: ''; position: absolute; top: 50%; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, rgba(248,113,113,0.2) 0%, rgba(96,165,250,0.2) 50%, rgba(52,211,153,0.2) 100%); z-index: 0; }
    .chain-node { flex: 1; border-radius: 12px; padding: 16px; display: flex; flex-direction: column; align-items: center; gap: 12px; text-align: center; position: relative; z-index: 1; backdrop-filter: blur(8px); transition: transform 0.3s; }
    .chain-node:hover { transform: translateY(-4px); }
    .chain-arrow { color: rgba(255,255,255,0.2); font-weight: 300; padding: 0; font-size: 24px; position: relative; z-index: 1; display: none; }
    
    .node-red { background: linear-gradient(180deg, rgba(30, 15, 20, 0.8) 0%, rgba(15, 10, 15, 0.9) 100%); border: 1px solid rgba(248, 113, 113, 0.2); box-shadow: 0 8px 24px rgba(220, 38, 38, 0.15); }
    .node-blue { background: linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(10, 15, 30, 0.9) 100%); border: 1px solid rgba(96, 165, 250, 0.2); box-shadow: 0 8px 24px rgba(37, 99, 235, 0.15); }
    .node-purple { background: linear-gradient(180deg, rgba(25, 15, 45, 0.8) 0%, rgba(15, 10, 30, 0.9) 100%); border: 1px solid rgba(167, 139, 250, 0.2); box-shadow: 0 8px 24px rgba(124, 58, 237, 0.15); }
    .node-green { background: linear-gradient(180deg, rgba(10, 35, 25, 0.8) 0%, rgba(5, 20, 15, 0.9) 100%); border: 1px solid rgba(52, 211, 153, 0.2); box-shadow: 0 8px 24px rgba(5, 150, 105, 0.15); }
    
    .chain-icon { font-size: 12px; font-weight: 700; font-family: 'Outfit', sans-serif; letter-spacing: 1px; width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
    .node-red .chain-icon { background: rgba(248, 113, 113, 0.15); color: #F87171; border: 1px solid rgba(248, 113, 113, 0.3); }
    .node-blue .chain-icon { background: rgba(96, 165, 250, 0.15); color: #60A5FA; border: 1px solid rgba(96, 165, 250, 0.3); }
    .node-purple .chain-icon { background: rgba(167, 139, 250, 0.15); color: #A78BFA; border: 1px solid rgba(167, 139, 250, 0.3); }
    .node-green .chain-icon { background: rgba(52, 211, 153, 0.15); color: #34D399; border: 1px solid rgba(52, 211, 153, 0.3); }
    
    .chain-text h4 { margin: 0; font-size: 0.95rem; font-weight: 600; color: #F8FAFC; letter-spacing: 0.2px; }
    .chain-text p { margin: 6px 0 0 0; font-size: 0.75rem; color: #94A3B8; line-height: 1.4; font-weight: 400; }
    
    .evidence-box { background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(255, 255, 255, 0.05); padding: 20px; border-radius: 12px; display: flex; gap: 16px; align-items: flex-start; backdrop-filter: blur(8px); margin-top: 10px; }
    .evidence-content h4 { margin: 0 0 8px 0; color: #F8FAFC; font-size: 0.95rem; font-weight: 600; }
    .evidence-content p { margin: 0; font-size: 0.85rem; color: #94A3B8; line-height: 1.6; }
    .evidence-quote { margin-top: 12px; padding: 12px 16px; background: rgba(255,255,255,0.02); border-left: 2px solid #8B5CF6; border-radius: 0 8px 8px 0; color: #CBD5E1; font-style: italic; font-size: 0.85rem; font-family: monospace; }
    </style>
    """
    chain_html = f"""
    {chain_css}
    <h3 style="margin: 10px 0 15px 0; display: flex; align-items: center; gap: 8px;">Adaptive Chain Detected</h3>
    <div class="chain-container">
        <div class="chain-node node-red">
            <div class="chain-icon">01</div>
            <div class="chain-text">
                <h4>{cause}</h4>
                <p>Produces {effect.lower()}</p>
            </div>
        </div>
        <div class="chain-arrow">→</div>
        <div class="chain-node node-blue">
            <div class="chain-icon">02</div>
            <div class="chain-text">
                <h4>{effect}</h4>
                <p>Valid session obtained</p>
            </div>
        </div>
        <div class="chain-arrow">→</div>
        <div class="chain-node node-purple">
            <div class="chain-icon">03</div>
            <div class="chain-text">
                <h4>{target_disp}</h4>
                <p>Tests access to other users' data</p>
            </div>
        </div>
        <div class="chain-arrow">→</div>
        <div class="chain-node node-green">
            <div class="chain-icon">04</div>
            <div class="chain-text">
                <h4>Unauthorized Access</h4>
                <p>Access to unauthorized data confirmed</p>
            </div>
        </div>
    </div>
    <div class="evidence-box">
        <div class="evidence-content">
            <h4>Agent Decision Evidence</h4>
            <p>The agent dynamically decided to run the {target} check after {clean_reason.lower()}, as shown in the decision log.</p>
            <div class="evidence-quote">"{chain_text}"</div>
        </div>
    </div>
    """
    st.markdown(chain_html.replace('\n', ''), unsafe_allow_html=True)
st.divider()

# Risk & Impact Analysis
st.subheader("Risk & Impact Analysis")

risk_assessments = state.get("risk_assessments", [])

if risk_assessments:
    for risk in risk_assessments:
        category = str(
            risk.get("category", "Unknown")
        ).upper()

        with st.expander(category):
            st.write(
                f"**Impact:** "
                f"{risk.get('impact', 'Not available')}"
            )

            st.write(
                f"**Recommended Remediation:** "
                f"{risk.get('remediation', 'Not available')}"
            )
else:
    st.info("No risk analysis available.")

st.divider()
# Detailed findings
with st.expander("View Detailed Findings"):
    if findings:
        import copy
        for finding in findings:
            safe_finding = copy.deepcopy(finding)
            if isinstance(safe_finding.get("data"), dict) and "token" in safe_finding["data"]:
                safe_finding["data"]["token"] = "[REDACTED JWT]"
            st.json(safe_finding)
    else:
        st.info("No findings recorded.")
# Decision log
with st.expander("View Complete AI Decision Log"):
    if decision_log:
        for entry in decision_log:
            st.write(entry)
    else:
        st.info("No decision log available.")
# Report
with st.expander("View Security Assessment Report"):
    try:
        import html
        lines = []
        lines.append("=" * 60)
        lines.append(f"SECURITY ASSESSMENT REPORT — {state.get('target_url', 'N/A')}")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Modules run: {', '.join(modules)}")
        lines.append(f"Total steps taken: {state.get('step_count', 0)}")
        lines.append("")
        lines.append("--- FINDINGS ---")
        if not findings:
            lines.append("No findings recorded.")
        else:
            import copy
            for f in findings:
                ftype = f.get("finding_type", "unknown")
                data = copy.deepcopy(f.get("data", {}))
                if isinstance(data, dict) and "token" in data:
                    data["token"] = "[REDACTED JWT]"
                if ftype == "xss" and isinstance(data, dict) and "payload" in data:
                    payload = data.get("payload", "")
                    # Escape HTML to ensure it renders as text and doesn't disappear
                    lines.append(f"  - [{ftype}] Payload: {payload}")
                    lines.append(f"    Full Data: {data}")
                else:
                    lines.append(f"  - [{ftype}] {data}")
        lines.append("")
        lines.append("--- REASONING TRAIL (why each action was taken) ---")
        if decision_log:
            for entry in decision_log:
                lines.append(f"  - {entry}")
        else:
            lines.append("No decision log available.")
        report_str = "\n".join(lines)
        # Escape the entire report to prevent Markdown/HTML interpretation of dictionaries or tags
        escaped_report = html.escape(report_str)
        # Render using a pre-wrap div so it acts as plain text, wraps lines, and avoids SVG copy bugs
        st.markdown(
            f"<div style='white-space: pre-wrap; font-family: monospace; background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px;'>{escaped_report}</div>", 
            unsafe_allow_html=True
        )
        st.download_button(
            "Download Report",
            data=report_str,
            file_name="security_assessment_report.txt",
            mime="text/plain"
        )
    except Exception as e:
        st.error(
            f"Unable to generate report: {e}"
        )