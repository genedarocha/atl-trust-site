# ATL-Trust Feature Documentation

**ATL-Trust** is an enterprise-grade, hardware-attested **Zero-Trust Policy Enforcement Point (PEP) and Policy Decision Point (PDP) Platform** for autonomous AI agents. It protects production systems (blockchains, cloud infrastructure, databases, and enterprise APIs) by continuously validating AI agent tool invocations, intent proposals, and fiscal actions before execution.

---

## 📋 Table of Contents

1. [Architectural Overview](#-architectural-overview)
2. [Core Platform Features](#-core-platform-features)
   - [1. Hardware-Attested Baseline PEP (Rust Core)](#1-hardware-attested-baseline-pep-rust-core)
   - [2. Grok-Powered Secondary Intent Judge (xAI Grok-4.6)](#2-grok-powered-secondary-intent-judge-xai-grok-46)
   - [3. Flexible 3-Tier Validation Modes](#3-flexible-3-tier-validation-modes)
   - [4. Fail-Closed Security & Configurable Fallback (`GROK_FAIL_MODE`)](#4-fail-closed-security--configurable-fallback-grok_fail_mode)
   - [5. Multi-Agent Debate Verification Engine](#5-multi-agent-debate-verification-engine)
   - [6. Cryptographic Tamper-Proof Audit Ledger](#6-cryptographic-tamper-proof-audit-ledger)
   - [7. Developer SDK & Framework Integrations](#7-developer-sdk--framework-integrations)
   - [8. Metrics & Observability Suite](#8-metrics--observability-suite)
   - [9. Real-Time Risk Dashboard & Interactive Consoles](#9-real-time-risk-dashboard--interactive-consoles)
   - [10. Confidential Edge Data Redaction Sandbox](#10-confidential-edge-data-redaction-sandbox)
   - [11. Enterprise Regulatory Compliance (EU AI Act, MiCA, DORA, GDPR)](#11-enterprise-regulatory-compliance-eu-ai-act-mica-dora-gdpr)
3. [SDK Usage Examples](#-sdk-usage-examples)
4. [Deployment Options](#-deployment-options)

---

## 🏗️ Architectural Overview

ATL-Trust introduces a dual-layer Zero-Trust Policy Decision Point (PDP) model:

```
[ Autonomous AI Agent ] ---> [ ATL-Trust Python Interceptor ] ---> [ ATL-Trust PEP Orchestrator ]
                                                                                |
                                               +--------------------------------+--------------------------------+
                                               |                                                                 |
                                 [ Baseline Hardware-Attested Rust PEP ]                        [ xAI Grok Secondary Judge ]
                                 - Single Transaction Caps ($5,000 max)                          - Semantic Intent Drift Detection
                                 - Asset Class Allowlists (USDC, ETH, BTC)                        - Prompt Injection Defense
                                 - Sandbox Attestation Verification                               - Risk Scoring (0.0 to 1.0)
                                 - Dynamic Volume Circuit Breaker                                  - Multi-Agent Debate Engine
                                               |                                                                 |
                                               +--------------------------------+--------------------------------+
                                                                                |
                                                                   [ Decision Engine ]
                                                             ALLOW / DENY / HUMAN_APPROVAL
                                                                                |
                                                                                v
                                                            [ Cryptographic Tamper-Proof Ledger ]
```

---

## 🌟 Core Platform Features

### 1. Hardware-Attested Baseline PEP (Rust Core)
* **Sub-5ms Execution Latency:** Built with high-performance Rust (`atl-trust-core`) for minimal overhead in real-time trading or API workflows.
* **Fiscal Transaction Caps:** Automatically enforces single-transaction monetary ceilings (e.g. max $5,000 per tool execution).
* **Asset Class Allowlisting:** Restricts financial tool execution to predefined, safe token/currency allowlists (e.g., `USDC`, `ETH`, `BTC`).
* **Hardware/Sandbox Attestation Verification:** Validates Signed Trusted Execution Environment (TEE) attestation tokens (e.g. `SANDBOX-ACTIVE-*`) to ensure agent code runs inside isolated hardware enclaves.
* **Dynamic Circuit Breakers:** Monitors cumulative transaction volume over time and automatically trips to block execution if aggregate limits (e.g., $10,000 total volume) are breached.

### 2. Grok-Powered Secondary Intent Judge (`xAI Grok-4.6`)
* **Semantic Intent Drift Detection:** Evaluates agent task goals against proposed tool calls to detect rogue behavior, hallucinations, or unapproved goal alterations.
* **Prompt Injection Hijack Defense:** Deep reasoning analysis catches prompt injection attacks, indirect prompt manipulation, and obfuscated payload injections before tool execution.
* **Fine-Grained Risk Scoring:** Computes risk scores from `0.0` (completely safe) to `1.0` (critical threat) accompanied by human-readable decision rationales.

### 3. Flexible 3-Tier Validation Modes
* ⚡ **`rules` Mode (Baseline PEP):** Runs 100% hardware-attested Rust policy checks. Offers maximum speed (<5ms) for trusted, internal workflows.
* 🤖 **`grok` Mode (Full Intent Judge):** Evaluates every single tool invocation through xAI Grok-4.6 for deep semantic reasoning.
* 🔀 **`hybrid` Mode (Smart Escalation):** Executes fast baseline rules on low-risk actions and dynamically escalates sensitive actions (e.g., high transaction values, admin privileges, transfers, code execution) to Grok.

### 4. Fail-Closed Security & Configurable Fallback (`GROK_FAIL_MODE`)
Guarantees system safety even during external API downtime or network splits via four configurable fallback policies:
* **`deny` (Default):** Fail-closed approach; rejects tool calls if the Grok API is unreachable or times out.
* **`rules`:** Reverts strictly to hardware-attested Rust PEP rules when Grok is offline.
* **`require_human`:** Pauses transaction execution and queues it for human-in-the-loop validation.
* **`allow`:** Fail-open mode reserved strictly for non-critical testing environments.

### 5. Multi-Agent Debate Verification Engine
For high-risk, high-value, or ambiguous transactions, ATL-Trust initiates an automated dual-agent security debate adjudicated by Grok:
* **Security Auditor Agent:** Scrutinizes the proposed action, searching for injection risks, parameter tampering, and policy violations.
* **Proponent Agent:** Formulates a defense explaining how the tool call fulfills the user's explicit task goal.
* **Grok Adjudicator:** Reviews both arguments, weighs security implications against operational goals, and renders a final binding `ALLOW` or `DENY` verdict.

### 6. Cryptographic Tamper-Proof Audit Ledger
* **SHA-256 Ledger Hashing:** Generates an immutable, cryptographic chain of records for every agent intent, tool argument, decision rationale, risk score, and timestamp.
* **TEE Signature Binding:** Cryptographically signs audit records with hardware enclave keys to prevent post-hoc tampering.

### 7. Developer SDK & Framework Integrations
* **Python SDK (`atl_trust`):** Complete programmatic API for orchestrator setup, policy configuration, and execution interceptors.
* **`@atl_trust_guardrail` Decorator:** Simple Python function wrapper to protect native Python functions with Zero-Trust PEP validation.
* **Framework Interceptors & Adapters:** Out-of-the-box integrations for **LangGraph**, **CrewAI**, **AutoGen**, and custom LLM agent loops.

### 8. Metrics & Observability Suite
* **`ValidationMetricsTracker`:** Collects real-time telemetry on total validations, decision counts (`ALLOW`/`DENY`), average latency in milliseconds, fallback event frequencies, and cumulative financial volume processed.

### 9. Real-Time Risk Dashboard & Interactive Consoles
* **Visual Telemetry Dashboard (`dashboard.html`):** SVG-based overall risk score gauges, threat level breakdowns, real-time audit log stream, and interactive threat category heatmaps.
* **Cryptographic Ledger Console (`index.html`):** Interactive UI for searching, filtering, and verifying signed ledger hash chains.

### 10. Confidential Edge Data Redaction Sandbox
* **PII & Sensitive Data Redaction:** Interactive edge console for stripping sensitive user data, PII, and credentials before sending context to external LLM providers.

### 11. Enterprise Regulatory Compliance (EU AI Act, MiCA, DORA, GDPR)
* Designed to help enterprise AI teams satisfy governance, oversight, risk management, and auditability requirements under the **EU AI Act** (Article 6 High-Risk AI requirements), **GDPR**, **MiCA**, and **DORA**.
* Includes a knowledge base and store of 20+ specialized compliance manuals and checklists (`store.html`).

---

## 💻 SDK Usage Examples

### 1. Tool Call Interception
```python
from atl_trust import ATLTrustConfig, ATLTrustOrchestrator, ATLTrustToolInterceptor

# Initialize orchestrator from environment variables
config = ATLTrustConfig.from_env()
orchestrator = ATLTrustOrchestrator(config=config)
interceptor = ATLTrustToolInterceptor(orchestrator)

# Intercept and validate a proposed tool call before execution
result = interceptor.intercept_and_validate(
    tool_name="execute_transfer",
    arguments={"recipient": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "amount": 150.0},
    intent_reasoning="Vendor invoice payment",
    asset="USDC",
    value=150.0,
    task_goal="Pay monthly cloud hosting bill"
)

if result.allowed:
    print(f"✅ Approved via {result.validator_used}")
else:
    print(f"🚨 Blocked: {result.reason}")
```

### 2. Decorator Guardrail
```python
from atl_trust import atl_trust_guardrail

@atl_trust_guardrail(asset="USDC", value_arg="amount")
def transfer_funds(recipient: str, amount: float, reason: str = ""):
    # Code executes ONLY if ATL-Trust PEP + Grok approves
    return f"Transferred ${amount} to {recipient}"

try:
    transfer_funds(recipient="0x123...", amount=250.0, reason="Cloud invoice")
except PermissionError as e:
    print(f"Guardrail Blocked Action: {e}")
```

---

## 🐳 Deployment Options

* **Docker & Docker Compose:** Orchestrates both the Rust hardware-attested microservice (`atl-trust-core`) and Python PEP orchestrators seamlessly.
* **Cloud Enclave Blueprints:** Supports deployment inside Google Cloud Confidential VMs, AWS Nitro Enclaves, Azure TEEs, and Civo Kubernetes clusters.
