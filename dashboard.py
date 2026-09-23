import streamlit as st
import plotly.graph_objects as go

from agent import app
from state import initial_state

st.set_page_config(
    page_title="Adaptive AI Agent",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Adaptive AI Agent")
st.caption("Multistep Web Application Penetration Testing")
st.divider()

# Sidebar
with st.sidebar:
    st.header("🛡️ Adaptive AI Agent")
    st.caption("AI-powered multistep web application security assessment")

    st.subheader("Scan Control")

    target = st.text_input(
        "Target URL",
        value="http://localhost:3000"
    )

    start_scan = st.button(
        "▶ Start New Scan",
        use_container_width=True,
        type="primary"
    )

    clear_results = st.button(
        "↻ Clear Results",
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
        st.subheader("🔍 Reconnaissance")
        st.write("Fingerprinting and web crawling")

    with col2:
        st.subheader("🚨 Assessment")
        st.write("Authentication and vulnerability checks")

    with col3:
        st.subheader("🤖 Adaptive AI")
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
st.subheader("📊 Assessment Overview")

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
    st.subheader("🔄 Module Execution")

    module_names = {
        "fingerprint": "🔍 Fingerprinting",
        "crawl": "🕷️ Web Crawling",
        "auth_check": "🔐 Authentication Check",
        "idor_check": "🎯 IDOR Check",
        "sqli_check": "💉 SQL Injection Check",
        "xss_check": "🧪 XSS Check"
    }

    for i, module in enumerate(modules, 1):
        st.success(
            f"{i}. {module_names.get(module, module)}"
        )

with middle:
    st.subheader("🚨 Vulnerability Overview")

    if findings:
        for finding in findings:
            finding_type = finding.get("finding_type", "unknown")
            data = finding.get("data", {})
            vulnerable = (
                isinstance(data, dict)
                and data.get("vulnerable") is True
            )

            if vulnerable:
                st.error(
                    f"🔴 {finding_type.upper()} — VULNERABLE"
                )
                if isinstance(data, dict) and data.get("detail"):
                    st.caption(data["detail"])
            else:
                st.success(
                    f"🟢 {finding_type.upper()} — PASSED"
                )
    else:
        st.info("No findings recorded.")

with right:
    st.subheader("🤖 AI Decision Trail")

    if decision_log:
        for entry in decision_log:
            if "CHAINED" in entry:
                st.info(f"🔗 {entry}")
            else:
                st.write(f"• {entry}")
    else:
        st.info("No decision log available.")

st.divider()

# Reconnaissance
st.subheader("🔍 Reconnaissance Results")

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
    with st.expander("⚠️ View Unusual / Leaked Headers"):
        for header in unusual_headers:
            st.code(header)

# Discovered pages
st.subheader("🕷️ Discovered Pages & Resources")

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
        st.code(page)
else:
    st.info("No pages/resources discovered.")

st.divider()

# Adaptive chain
st.subheader("🔗 Adaptive AI Chain")

idor_ran = "idor_check" in modules

if idor_ran:
    a, b, c = st.columns(3)

    with a:
        st.success("🔐 Authentication\n\nSession obtained")

    with b:
        st.info("🔑 TOKEN\n\nValid session")

    with c:
        st.warning("🎯 IDOR\n\nAutomatically Triggered")

    st.success(
        "The agent detected a valid session and automatically chained the IDOR module."
    )
else:
    st.info("No adaptive chain was triggered during this assessment.")

# Finding chart
st.divider()
chart_col, summary_col = st.columns(2)

with chart_col:
    st.subheader("📊 Finding Distribution")

    counts = {}

    for finding in findings:
        finding_type = finding.get(
            "finding_type",
            "unknown"
        )
        counts[finding_type] = counts.get(
            finding_type,
            0
        ) + 1

    if counts:
        fig = go.Figure(
            data=[
                go.Pie(
                    labels=[
                        x.upper()
                        for x in counts.keys()
                    ],
                    values=list(counts.values()),
                    hole=0.55
                )
            ]
        )

        fig.update_layout(
            template="plotly_dark",
            height=320,
            margin=dict(
                l=10,
                r=10,
                t=10,
                b=10
            )
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )
    else:
        st.info("No findings to chart.")

with summary_col:
    st.subheader("📋 Assessment Summary")

    st.write(
        "**Target:**",
        state.get("target_url", "N/A")
    )
    st.write(
        "**Modules Executed:**",
        len(modules)
    )
    st.write(
        "**Total Steps:**",
        state.get("step_count", 0)
    )
    st.write(
        "**Total Findings:**",
        len(findings)
    )
    st.write(
        "**Confirmed Vulnerabilities:**",
        len(vulnerabilities)
    )

# Baseline comparison
st.divider()
st.subheader("⚖️ Baseline vs Adaptive Agent")

b1, b2 = st.columns(2)

with b1:
    st.write("### BASELINE")
    st.caption("Chaining Disabled")
    st.write("Core modules: 5")
    st.write("IDOR: Not automatically triggered")

with b2:
    st.write("### ADAPTIVE AGENT")
    st.caption("Chaining Enabled")
    st.write(f"Modules executed: {len(modules)}")
    st.write(
        "IDOR: Automatically triggered"
        if idor_ran
        else "IDOR: Not triggered in this scan"
    )

st.divider()

# Detailed findings
with st.expander("📋 View Detailed Findings"):
    if findings:
        for finding in findings:
            st.json(finding)
    else:
        st.info("No findings recorded.")

# Decision log
with st.expander("🧠 View Complete AI Decision Log"):
    if decision_log:
        for entry in decision_log:
            st.write(entry)
    else:
        st.info("No decision log available.")

# Report
with st.expander("📄 View Security Assessment Report"):
    try:
        from modules.report import generate_report

        report = generate_report(state)

        st.code(
            report,
            language="text"
        )

        st.download_button(
            "⬇️ Download Report",
            data=report,
            file_name="security_assessment_report.txt",
            mime="text/plain"
        )

    except Exception as e:
        st.error(
            f"Unable to generate report: {e}"
        )
