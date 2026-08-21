# ATL-Trust | Zero-Trust AI Agent Security & Validation Platform

[![Build & Test](https://img.shields.io/badge/tests-22%20passed-brightgreen.svg)](tests/test_atl_trust.py)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/security-hardware--attested%20%2B%20multi--llm-purple.svg)](#architecture)

**ATL-Trust** is an enterprise-grade, hardware-attested **Zero-Trust Policy Enforcement Point (PEP) and Policy Decision Point (PDP) Platform** built specifically for **FinTech, Crypto/DeFi, and Enterprise API Automation Swarm Developers**—teams that lose real money or compromise production infrastructure when an autonomous AI agent executes an unauthorized tool call.

By treating every AI agent, tool invocation, and financial action as untrusted by default, ATL-Trust continuously verifies identity, validates intent, prevents prompt injection drift, enforces least-privilege scoping, and executes circuit breaker tripwires before actions hit production blockchains, databases, or enterprise APIs.

---

## 🌟 Key Features

* 🛡️ **Hardware-Attested Baseline PEP (Rust Core):** Ultra-low latency (<5ms) baseline validation of fiscal caps, asset allowlists, AWS Nitro / GCP Confidential VM / Intel SGX attestation verification, and SHA-256 hash ledger integrity.
* 🤖 **Pluggable Secondary Intent Judge (`xAI Grok`, `OpenAI GPT-4o`, `Anthropic Claude 3.5`, `Ollama/vLLM`):** Deep reasoning evaluation of agent task goals vs proposed tool calls to catch semantic intent drift, prompt injection exploits, and stealthy agent rogue behavior.
* ⚡ **3 Flexible Validation Modes:** `rules` (100% pure hardware rules), `grok` (full LLM intent verification), and `hybrid` (rules-first, LLM on high-risk/uncertain calls).
* 🔒 **Fail-Closed Security (`GROK_FAIL_MODE`):** Configurable error handling on API timeouts or network splits (`deny`, `allow`, `require_human`, `rules`).
* ⚖️ **Multi-Agent Debate Verification:** Simulates real-time Security Auditor vs Proponent debates adjudicated by secondary LLM judges before authorizing high-risk financial or system actions.
* 🔌 **LangGraph & Generic Agent Adapters:** Easy integration for LangGraph, CrewAI, AutoGen, or custom Python tool calls via interceptors or `@atl_trust_guardrail` decorators.
* 📜 **Tamper-Proof SHA-256 Ledger:** Immutable cryptographic log of all approved and rejected intents signed with TEE signatures.

---

## 🏗️ Architecture Overview

```
                        +---------------------------------------------+
                        |           Autonomous AI Agent               |
                        |      (LangGraph / CrewAI / Custom)          |
                        +---------------------------------------------+
                                               |
                                (Tool Call / Intent Proposal)
                                               v
                        +---------------------------------------------+
                        |      ATL-Trust Python Interceptor           |
                        +---------------------------------------------+
                                               |
                                               v
                        +---------------------------------------------+
                        |      ATL-Trust Orchestrator PEP Core        |
                        +---------------------------------------------+
                                /                             \
                               /                               \
     +-----------------------------------+           +-----------------------------------+
     | Baseline PEP Rules (Rust Node)    |           | Grok Secondary Judge (xAI API)    |
     | - Fiscal Limits ($5,000 max)      |           | - Intent Drift Detection          |
     | - Allowed Assets (USDC, ETH, BTC) |           | - Risk Scoring (0.0 to 1.0)       |
     | - Sandbox Attestation Verification|           | - Deep Reasoning Policy Check     |
     | - Volume Circuit Breaker ($10,000)|           | - Multi-Agent Debate Engine       |
     +-----------------------------------+           +-----------------------------------+
                                \                               /
                                 \                             /
                                               v
                        +---------------------------------------------+
                        |    Decision: ALLOW / DENY / HUMAN_APPROVAL  |
                        |    + Append to Immutable Cryptographic Ledger|
                        +---------------------------------------------+
                                               |
                                               v
                        +---------------------------------------------+
                        |    Execution Layer (Blockchain / CEX / API) |
                        +---------------------------------------------+
```

> [!NOTE]
> **Non-Breaking Architecture:** The Grok validation layer sits strictly *on top* of the authoritative hardware-attested Rust PEP. Baseline cryptographic attestation and fiscal checks are evaluated first. Grok cannot override a hard baseline rule denial.

---

## ⚙️ Configuration & Environment Variables

ATL-Trust is configured via clean environment variables:

| Environment Variable | Options / Default | Description |
| :--- | :--- | :--- |
| `ATL_TRUST_VALIDATOR` | `rules` (default), `grok`, `hybrid` | Core operational mode. `rules` runs baseline PEP; `grok` runs Grok on every call; `hybrid` calls Grok only on high-risk calls. |
| `XAI_API_KEY` | `xai-...` | Required when running in `grok` or `hybrid` mode. |
| `GROK_MODEL` | `grok-4.6` (default) | Flagship xAI Grok model used for intent validation & debate adjudication. |
| `GROK_TIMEOUT_SECONDS` | `8` (default) | Timeout limit in seconds for Grok API calls. |
| `GROK_FAIL_MODE` | `deny` (default), `allow`, `require_human`, `rules` | Fallback behavior when Grok API is unreachable or times out. |
| `ATL_TRUST_CORE_URL` | `http://localhost:3000` | URL of the Rust hardware-attested validator microservice. |

### Example `.env` File
```bash
ATL_TRUST_VALIDATOR=hybrid
XAI_API_KEY=xai-your-api-key-here
GROK_MODEL=grok-4.6
GROK_TIMEOUT_SECONDS=8
GROK_FAIL_MODE=deny
ATL_TRUST_CORE_URL=http://localhost:3000
```

---

## 🚀 Quick Start (Python SDK)

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/voxstar-labs/atl-trust-site.git
cd atl-trust-site
```

### 2. Basic Tool Call Interception
```python
from atl_trust import ATLTrustConfig, ATLTrustOrchestrator, ATLTrustToolInterceptor

# 1. Initialize Orchestrator from environment
config = ATLTrustConfig.from_env()
orchestrator = ATLTrustOrchestrator(config=config)
interceptor = ATLTrustToolInterceptor(orchestrator)

# 2. Intercept and validate a proposed tool call
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

### 3. Decorator Usage (`@atl_trust_guardrail`)
```python
from atl_trust import atl_trust_guardrail

@atl_trust_guardrail(asset="USDC", value_arg="amount")
def transfer_funds(recipient: str, amount: float, reason: str = ""):
    # This code executes ONLY if ATL-Trust PEP + Grok approves
    return f"Transferred ${amount} to {recipient}"

# Automatically validated before invocation:
try:
    transfer_funds(recipient="0x123...", amount=250.0, reason="Cloud invoice")
except PermissionError as e:
    print(f"Guardrail Blocked Action: {e}")
```

---

## 🧪 Testing

Run the automated test suite covering all 3 validation modes, Grok fallback handling, metrics tracking, and decorators:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

---

## 🐳 Docker Deployment

Spin up both the Rust hardware-attested validator node and the Grok Python orchestrator:

```bash
docker compose up --build -d
```

---

## 📄 License

MIT License. Developed by Voxstar Labs.
