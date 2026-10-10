# Adaptive AI Agent for Multi-Step Web Application Penetration Testing

An AI-driven web-application security assessment agent that **adapts its testing
strategy from the evidence it gathers**, rather than running a fixed checklist.
An attack graph ranks candidate actions from the discovered attack surface and
accumulated findings; a large language model (GPT-OSS 120B via Groq) then
chooses the next action and reasons about the results. Its headline capability
is **multi-step chaining** — a verified SQL-injection authentication bypass is
turned into an authenticated session that drives follow-on IDOR (broken
object-level authorization) testing.

> **Authorized use only.** This project targets a local, intentionally
> vulnerable application (OWASP Juice Shop at `http://localhost:3000`). Do not
> run it against systems you do not own or have explicit permission to test.

---

## 1. What problem it addresses

Traditional automated scanners (DAST) are weak at exactly the things this agent
focuses on:

| Scanner limitation | This project |
|---|---|
| No multi-step / stateful chaining | SQLi → authenticated session → IDOR, carried across modules |
| Poor at access-control bugs (BOLA/IDOR) | Ownership-aware IDOR + authorization baseline comparison + user enumeration |
| Fixed, non-adaptive order | Attack graph scores candidates; LLM genuinely chooses the next action |
| High false positives, no confidence grading | Honest **confirmed / suspected / potential** grading; control-verified SQLi bypass |
| No shared context between steps | Session and discovered emails flow between modules |

It is a **proof-of-concept of adaptive, evidence-driven chaining**, not a
general-purpose scanner.

---

## 2. Key features

- **Genuine LLM-driven orchestration.** The attack graph produces a ranked,
  evidence-annotated shortlist of candidate actions (scores are advisory); the
  LLM chooses the most valuable next action and justifies it. Recon runs first,
  and a *verified* exploit chain is always followed (deterministic reliability).
- **Adaptive SQLi → IDOR chain.** A SQL-injection authentication bypass that is
  **control-verified** (a benign wrong-password login must fail while the
  injection payload authenticates) produces a session that drives IDOR testing.
- **Ownership-aware IDOR.** Confirms true broken object-level authorization by
  comparing the authenticated user ID against each resource's owner, instead of
  flagging any HTTP 200.
- **Evidence grading.** Every finding is graded **confirmed / suspected /
  potential**, so unverified leads are never reported as confirmed vulns.
- **Computed severity (not hardcoded).** Severity = inherent impact × confidence
  + context (auth bypass, cross-user access, data exposure), mapped to
  CVSS-style bands. A confirmed IDOR outranks a potential DOM-XSS lead.
- **XSS with honest accounting.** Four distinct counts — raw endpoints →
  expanded candidates → analyzed → findings. Reflected / URL / fragment / stored
  XSS are verified live (dialog execution); JavaScript assets are routed to a
  DOM source→sink analyzer with **bounded live confirmation** (potential →
  confirmed only when a payload actually executes).
- **Authorization & authentication analysis.** Baseline (unauthenticated 401) vs
  authenticated (200) comparison for excessive data exposure; differential
  **user-enumeration** detection on the security-question endpoint.
- **AI-authored executive summary.** At the end of a run the LLM writes a
  professional narrative (risk posture, key findings, the attack chain,
  prioritized recommendations) from a redacted digest — with a deterministic
  fallback if the LLM is unavailable.
- **Token-efficient.** Low reasoning effort, per-agent completion caps, and
  trimmed prompts keep Groq usage small.
- **Secret-safe.** Session tokens/JWTs are redacted from findings, logs, the
  dashboard, and the report. The authenticated session is kept only in internal
  state for the IDOR step.
- **Streamlit dashboard & text report** with a Findings & Evidence panel,
  computed severities, the adaptive-chain visualization, and the AI summary.

---

## 3. Architecture

```text
            Streamlit dashboard  /  CLI (agent.py)
                          │
                 ┌────────▼─────────┐
                 │   Orchestrator   │  decide_next_module()
                 │    (agent.py)    │
                 └───┬─────────┬────┘
        ranked shortlist │     │ chosen action
                 ┌───────▼──┐  │
                 │  Attack  │  │
                 │  graph   │  │   modules/attack_graph.py
                 │ (scores) │  │
                 └──────────┘  │
                          ┌────▼───────────────────────────┐
                          │  Specialist agents + tools      │
                          │  recon · auth · sqli · xss ·    │
                          │  idor · authorization           │
                          └────┬────────────────────────────┘
                               │ findings + evidence
                      ┌────────▼─────────┐
                      │  Shared state    │  state.py
                      │  (findings,      │
                      │   pending_chain, │
                      │   metrics, ...)  │
                      └────────┬─────────┘
                               │
                    risk_engine (severity) → dashboard / report / AI summary
```

### Core components
| File | Role |
|---|---|
| `agent.py` | Orchestrator: `decide_next_module` (LLM choice over the graph shortlist), chain handling, module execution, executive summary, `run_agent`. |
| `modules/attack_graph.py` | Attack graph: node-type hypotheses, evidence/session-aware scoring, ranked chains. |
| `agents/<name>_agent.py` + `<name>_runner.py` | Per-module decision logic and run loops (recon, auth, sqli, idor, xss, authorization). |
| `tools/<name>_tools.py` | The actual tests (Playwright / HTTP) per module. |
| `state.py` | `AgentState` schema and initialization. |
| `modules/risk_engine.py` | Computed severity model + impact/remediation text. |
| `groq_key_manager.py` | One Groq key per agent, `reasoning_effort`/`max_tokens`, TLS trust (truststore). |
| `dashboard.py` | Streamlit UI: metrics, Findings & Evidence, severity, chain, AI summary, report. |

---

## 4. How the adaptive decision works

1. **Recon first** (deterministic) discovers the attack surface and seeds the graph.
2. The **attack graph** scores candidate modules from the surface and findings
   (e.g. IDOR scores ~0 until an authenticated session exists, then rises to the top).
3. The **LLM** receives the ranked, evidence-annotated shortlist and the state
   summary, and **chooses** the next action (it may pick a lower-scored option,
   or stop, with justification). Invalid choices fall back to the top graph action.
4. When a module reports a **verified exploit chain** (e.g. `sqli_to_idor`), the
   orchestrator stores it as a `pending_chain` and executes its follow-up
   **deterministically** — a confirmed chain is never skipped.

Demonstrated chain:
**SQL Injection (control-verified auth bypass) → authenticated session → IDOR →
ownership comparison → confirmed cross-user access.**

---

## 5. Assessment modules

| Module | What it does |
|---|---|
| **Recon** | Discovers endpoints, forms, parameters, JS assets, and classifies the attack surface (injection, client-side, auth, user, transaction, authorization). |
| **Auth** | Analyzes authentication endpoints; **differential user-enumeration** on the security-question endpoint (a real email discloses the question while a random one does not). |
| **SQL Injection** | Tests the login flow; a bypass is **confirmed** only on a visible SQL error, or **suspected (verified)** when a benign control login fails but the injection payload authenticates. |
| **IDOR** | Accesses basket objects with the acquired session and confirms **ownership mismatches** (authenticated user ≠ resource owner). |
| **XSS** | Reflected / URL / fragment / stored payloads verified by live dialog execution; JS assets analyzed for DOM source→sink flows with bounded live confirmation. |
| **Authorization** | Baseline (401) vs authenticated (200) comparison to flag excessive data exposure / broken access control. |

---

## 6. Severity model

Severity is **computed**, not a fixed per-type label
(`modules/risk_engine.py:compute_severity`):

```
score = inherent_impact(type) × confidence(status) + context_bonuses
```
- **Inherent impact:** sqli 9 · idor 8 · authorization 7 · xss 6 · auth 4
- **Confidence:** confirmed ×1.0 · suspected ×0.7 · potential ×0.5
- **Context bonuses:** auth-bypass verified +1.5 · cross-user access +0.8 ·
  multiple records exposed +0.6 · unauthenticated +0.5
- **Bands:** ≥9 CRITICAL · ≥7 HIGH · ≥4 MEDIUM · ≥0.1 LOW · else INFO

Example output: confirmed IDOR → **HIGH (8.8)**, control-verified SQLi bypass →
**HIGH (7.8)**, confirmed XSS → **MEDIUM (6.0)**, potential DOM-XSS → **LOW (3.0)**.

---

## 7. Installation (Windows PowerShell)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install truststore          # OS trust store for Groq TLS (see note below)
python -m playwright install chromium
```

### Environment variables
The key manager uses **one Groq API key per agent**. Create a `.env` in the
project root:

```env
GROQ_API_KEY_1=your_recon_key
GROQ_API_KEY_3=your_auth_key
GROQ_API_KEY_5=your_sqli_key
GROQ_API_KEY_7=your_idor_key
GROQ_API_KEY_9=your_xss_key
GROQ_API_KEY_11=your_authorization_key
GROQ_API_KEY_13=your_orchestrator_key
```
(The same key may be reused across all seven if desired.)

> **TLS note:** the Groq SDK verifies certificates against the bundled `certifi`
> CAs. On networks with a corporate/AV root CA this fails with
> `SSL: CERTIFICATE_VERIFY_FAILED`. `groq_key_manager.py` calls
> `truststore.inject_into_ssl()` so Python uses the OS trust store instead.

### Target
Run OWASP Juice Shop locally, e.g.:
```powershell
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

---

## 8. Running

```powershell
python agent.py              # headless CLI run (prints reasoning, findings, AI summary)
streamlit run dashboard.py   # interactive dashboard: Start New Scan
```

### Tests
Focused unit tests run without the LLM or a live target (mocked):
```powershell
venv\Scripts\python.exe -m pytest tests/test_severity.py tests/test_orchestrator_llm.py `
  tests/test_executive_summary.py tests/test_attack_graph_scoring.py tests/test_chain_history.py `
  tests/test_sqli_chain_trigger.py tests/test_auth_enumeration.py tests/test_dom_xss_analysis.py `
  tests/test_xss_classification.py tests/test_xss_url_parsing.py -q
```

---

## 9. Security considerations
- **API keys** live in `.env`, excluded from version control.
- **Session tokens / JWTs** are redacted from findings, logs, dashboard, and
  report; the live session is kept only in internal state for the IDOR step.
- **Credentials/payloads** target the authorized local environment only.

---

## 10. Honest limitations
- **Breadth:** a PoC — login SQLi, reflected/DOM XSS, basket IDOR, a few
  auth/authz heuristics; not a general-purpose scanner.
- **Single target:** validated against OWASP Juice Shop; generalization to
  arbitrary apps/SPAs is not yet demonstrated.
- **DOM XSS live confirmation** is best-effort (bounded attempts); unconfirmed
  leads stay "potential".
- **Orchestration:** the LLM genuinely chooses, but it chooses from a
  graph-ranked shortlist and a verified chain is deterministic — so adaptivity
  is graph-informed, not fully autonomous.

---

## 11. Future enhancements
- Broaden detection (stored XSS variants, more IDOR object types, non-login SQLi).
- Less target-specific recon for generalization beyond Juice Shop.
- Fully LLM-planned multi-stage strategies.
- Exportable PDF/HTML reports; persistent assessment history.

---

## 12. Disclaimer
For educational purposes and authorized security assessments only. Use it only
against systems you own or have explicit, documented permission to test. The
authors assume no liability for misuse.
