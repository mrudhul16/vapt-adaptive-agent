# Adaptive AI Agent for Multi-Step Web Application Penetration Testing

## 1. Project Overview
The **Adaptive AI Agent for Multi-Step Web Application Penetration Testing** is an intelligent security assessment tool that utilizes a large language model (LLM) integrated with a state-graph architecture to perform dynamic vulnerability scanning. Unlike traditional linear scanners, this agent dynamically adapts its assessment path based on the findings it uncovers during execution. By leveraging **GPT-OSS 120B through Groq** and orchestrating decision-making via **LangGraph**, the agent is capable of identifying attack vectors and executing follow-up modules automatically. 

This project is specifically intended for authorized local testing environments, providing a framework for exploring AI-driven security automation.

## 2. Key Features
- **AI-driven module selection:** Leverages an LLM to decide the next best security check based on the current context.
- **State-based decision making:** Maintains a continuous state graph of vulnerabilities, executed modules, and discovered endpoints.
- **Web fingerprinting:** Analyzes HTTP response headers and server technology.
- **Web crawling:** Discovers accessible endpoints and resources on the target application.
- **Authentication testing:** Evaluates basic login endpoint security.
- **SQL injection detection:** Tests for authentication bypass vulnerabilities via SQL injection.
- **Adaptive SQLi → IDOR chaining:** Dynamically chains a successful SQL injection authentication bypass into a subsequent IDOR assessment.
- **Ownership-aware IDOR detection:** Cross-references basket access against the actual authenticated user ID to confirm true ownership violations.
- **DOM XSS detection using Playwright:** Uses a headless browser to execute and verify Cross-Site Scripting payloads.
- **Baseline vs Adaptive evaluation:** Provides a direct experimental comparison between linear execution and adaptive chaining.
- **Streamlit dashboard:** A comprehensive local UI displaying metrics, vulnerabilities, reasoning logs, and decision trees.
- **Security assessment report:** Generates a detailed text-based report summarizing the findings.
- **JWT redaction in dashboard/report output:** Automatically redacts sensitive session tokens from the UI and generated reports.

## 3. System Architecture
The agent is built on a directed state graph orchestrated by LangGraph. 

```text
User
 ↓
Streamlit Dashboard / CLI
 ↓
LangGraph Agent
 ↓
Agent State
 ↓
Decision Node
 ↓
Execution Node
 ↓
Security Modules
 ↓
Findings
 ↓
State Update
 ↓
Next Decision
 ↓
Dashboard / Report
```

### Core Components:
- **`agent.py`**: Defines the LangGraph state machine, the decision node (LLM), and the execution flow.
- **`state.py`**: Defines the `AgentState` schema and initialization logic.
- **`evaluation.py`**: A CLI script that runs and compares the Baseline (linear) and Adaptive (chained) execution modes.
- **`dashboard.py`**: The Streamlit frontend visualizing findings, module execution, and the AI decision trail.
- **`modules/recon.py`**: Houses the fingerprinting and crawling assessment modules.
- **`modules/vuln_assess.py`**: Houses active vulnerability testing modules (Authentication, SQLi, IDOR, XSS).
- **`modules/report.py`**: Logic for generating the final textual Security Assessment Report.

## 4. Adaptive Decision Making
The core innovation of this project is its ability to make runtime decisions. The agent maintains an active state containing:
- `modules_run`
- `findings`
- `pending_chains`
- `decision_log`
- `tech_stack`
- `step_count`
- `chaining_enabled`

When a vulnerability is found, the agent can trigger follow-up modules. In this implementation, the primary demonstrated chain is:

**SQL Injection → Authenticated Session → IDOR Check → Ownership Comparison → Unauthorized Basket Access**

The IDOR module is intelligently designed. It does not blindly flag HTTP 200 responses as vulnerable. Instead, it compares the `authenticated_user_id` extracted from the acquired session token against the target's `owner_user_id`. 

The agent dynamically outputs true authorization violations, such as:
- **Authenticated UserId:** 1
- **Unauthorized baskets:** 2, 3, 4, 5

## 5. Assessment Modules

| Module | Purpose |
|---|---|
| **Fingerprint** | Extracts technology stack information, server headers, and security headers. |
| **Crawl** | Discovers static assets, JS chunks, and accessible routes. |
| **Authentication Check** | Tests standard login capabilities and validates session token acquisition. |
| **SQL Injection** | Tests login endpoints for authentication bypass via SQL injection payloads. |
| **IDOR** | Tests Insecure Direct Object Reference by attempting to access cross-tenant data. |
| **XSS** | Tests DOM Cross-Site Scripting execution using Playwright to verify payload firing. |

## 6. Baseline vs Adaptive Evaluation
The project includes an experiment (`evaluation.py`) to measure the impact of adaptive chaining against a linear baseline.

**Observed Results:**

**BASELINE:**
- Modules Run: 5
- Total Steps: 5
- Total Findings: 5
- Vulnerabilities Confirmed: 2
- IDOR Executed: NO

**ADAPTIVE:**
- Modules Run: 6
- Total Steps: 6
- Total Findings: 6
- Vulnerabilities Confirmed: 3
- IDOR Executed: YES

*Explanation:* The adaptive mode intelligently executed an additional IDOR assessment because the SQL injection module produced an authenticated session. The baseline mode, lacking this adaptive reasoning, terminated after its static run. 

## 7. Dashboard
The local Streamlit application (`dashboard.py`) provides a rich, dark-themed UI to visualize the agent's performance.

Sections include:
- **System Status**: Displays current AI model (GPT-OSS 120B), framework (LangGraph), and runtime (Groq).
- **Module Execution**: Live tracking of completed assessment modules.
- **Vulnerability Overview**: Categorized display of passed and failed security checks.
- **IDOR Ownership Evidence**: Table displaying unauthorized cross-tenant data access.
- **Baseline vs Adaptive Agent**: A visual metric comparison of the two execution modes.
- **Adaptive Chain**: A visual flow-chart indicating how and why the AI chained modules together.
- **Agent Decision Evidence**: A raw log of the LLM's reasoning trail.
- **Security Assessment Report**: The raw, plain-text report output with safely escaped payloads.

## 8. Project Structure
```text
vapt-adaptive-agent/
│
├── agent.py
├── state.py
├── evaluation.py
├── dashboard.py
├── requirements.txt
├── .gitignore
├── modules/
│   ├── recon.py
│   ├── vuln_assess.py
│   └── report.py
├── test_groq_api.py
└── test_real_fingerprint.py
```

## 9. Installation

All commands are intended for Windows PowerShell.

1. **Create and activate a virtual environment:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. **Install dependencies:**
```powershell
pip install -r requirements.txt
```

3. **Install Playwright browsers:**
```powershell
python -m playwright install chromium
```

4. **Configure Environment Variables:**
Create a `.env` file in the root directory and add your Groq API key:
```env
GROQ_API_KEY=your_key_here
```

## 10. Running the Project

**Command Line Interface (CLI):**
Runs the core agent headlessly and prints the reasoning and findings to the console.
```powershell
python agent.py
```

**Evaluation Mode:**
Runs both the Baseline and Adaptive modes sequentially to demonstrate behavioral differences and outputs a comparative matrix.
```powershell
python evaluation.py
```

**Streamlit Dashboard:**
Launches the interactive web UI for configuring targets, running scans, and reviewing detailed visual reports.
```powershell
streamlit run dashboard.py
```

## 11. Test Environment
This project is hardcoded and configured to target an authorized local test environment:
`http://localhost:3000`

This project is strictly intended for authorized testing environments, such as a local intentionally vulnerable application (e.g., OWASP Juice Shop). Do not use this tool against unauthorized systems.

## 12. Security Considerations
- **API Keys:** The Groq API key is safely stored in `.env` and is strictly excluded from version control via `.gitignore`.
- **JWT Protection:** Session tokens (JWTs) obtained during testing are programmatically redacted from the Streamlit dashboard and generated reports to prevent accidental credential leakage in demonstrations.
- **Credentials:** Any hardcoded test credentials are for the authorized local test environment ONLY.

## 13. Limitations
- Current vulnerability modules target highly specific test cases and endpoints designed for the local sandbox.
- The IDOR testing module currently checks a constrained basket ID range (1-7).
- The agent's capabilities are currently demonstrated against the local Juice Shop environment.
- The evaluation currently demonstrates adaptive behavior exclusively for the implemented SQLi → IDOR chain.

## 14. Future Enhancements
- Addition of more vulnerability assessment modules.
- Implementation of complex, multi-stage adaptive attack chains.
- Broader and more dynamic endpoint discovery.
- Support for complex authentication scenarios (OAuth, SSO).
- Persistent assessment history across sessions.
- Expanded evaluation datasets.
- Exportable reporting features (PDF/HTML).

## 15. Results / Demonstration
*Example findings from a successful adaptive run:*

- **SQLi**: Vulnerable (Authentication bypass succeeded)
- **IDOR**: Vulnerable
  - **Authenticated User**: 1
  - **Unauthorized Baskets**: 2, 3, 4, 5
- **XSS**: Vulnerable
- **Adaptive Chain Triggered**: SQLi → Authenticated Session → IDOR

## 16. License / Disclaimer
**Disclaimer:** This tool is designed exclusively for educational purposes and authorized security assessments. You may only use this software against systems you own or have explicit, documented permission to test. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
