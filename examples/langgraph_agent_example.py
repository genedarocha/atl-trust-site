#!/usr/bin/env python3
"""
Example: Routing LangGraph / Generic AI Agent Tool Calls through ATL-Trust Proxy.

This script demonstrates how an AI agent executing tool calls (e.g. fund transfers,
database queries, or swaps) is intercepted and validated by ATL-Trust in real time.
"""

import os
import sys

# Add parent directory to sys.path to import atl_trust
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atl_trust import (
    ATLTrustConfig,
    ATLTrustOrchestrator,
    ATLTrustToolInterceptor,
    PolicyContext,
    atl_trust_guardrail,
)


def main():
    print("=" * 70)
    print("🚀 ATL-Trust Zero-Trust AI Agent Validation & Orchestration Platform")
    print("=" * 70)

    # 1. Initialize Configuration
    # You can change ATL_TRUST_VALIDATOR to "rules", "grok", or "hybrid"
    mode = os.getenv("ATL_TRUST_VALIDATOR", "hybrid")
    print(f"[*] Configured Mode: ATL_TRUST_VALIDATOR={mode}")

    config = ATLTrustConfig(
        validator_mode=mode,
        grok_model=os.getenv("GROK_MODEL", "grok-4.6"),
        grok_timeout_seconds=8.0,
        grok_fail_mode="deny",
        high_risk_value_threshold=500.0,  # Any tx >= $500 triggers Grok in hybrid mode
    )

    policy = PolicyContext(
        allowed_assets=["USDC", "ETH", "BTC"],
        max_tx_value=5000.0,
        circuit_breaker_threshold=10000.0,
    )

    orchestrator = ATLTrustOrchestrator(config=config, policy=policy)
    interceptor = ATLTrustToolInterceptor(orchestrator)

    # 2. Example 1: Intercepting a standard low-risk tool call ($150 USDC)
    print("\n--- [Scenario 1] Standard Low-Risk Tool Call ($150 USDC Transfer) ---")
    res1 = interceptor.intercept_and_validate(
        tool_name="execute_transfer",
        arguments={"recipient": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "amount": 150.0},
        intent_reasoning="Routine vendor payment approved in task workflow.",
        asset="USDC",
        value=150.0,
        task_goal="Pay vendor invoice #1042",
    )
    print(f"Decision: {res1.decision_code} | Allowed: {res1.allowed}")
    print(f"Validator Used: {res1.validator_used}")
    print(f"Reason: {res1.reason}")
    print(f"Latency: {res1.execution_time_ms:.2f}ms")

    # 3. Example 2: Intercepting a high-risk tool call ($1,500 USDC Transfer)
    print("\n--- [Scenario 2] High-Risk Escalated Tool Call ($1,500 USDC Transfer) ---")
    res2 = interceptor.intercept_and_validate(
        tool_name="execute_transfer",
        arguments={"recipient": "0x1234567890abcdef1234567890abcdef12345678", "amount": 1500.0},
        intent_reasoning="Large capital reallocation to external yield vault.",
        asset="USDC",
        value=1500.0,
        task_goal="Rebalance portfolio treasury",
    )
    print(f"Decision: {res2.decision_code} | Allowed: {res2.allowed}")
    print(f"Validator Used: {res2.validator_used}")
    print(f"Reason: {res2.reason}")
    print(f"Risk Score: {res2.risk_score}")

    # 4. Example 3: Intercepting an Unauthorized Asset Tool Call (SOL Token)
    print("\n--- [Scenario 3] Baseline Rule Violation (Unauthorized Asset: SOL) ---")
    res3 = interceptor.intercept_and_validate(
        tool_name="swap_tokens",
        arguments={"from_asset": "SOL", "to_asset": "USDC", "amount": 200.0},
        intent_reasoning="Swap unapproved asset SOL for USDC",
        asset="SOL",
        value=200.0,
        task_goal="Diversify holdings",
    )
    print(f"Decision: {res3.decision_code} | Allowed: {res3.allowed}")
    print(f"Validator Used: {res3.validator_used}")
    print(f"Reason: {res3.reason}")

    # 5. Example 4: Decorator Guardrail
    print("\n--- [Scenario 4] Using Decorator Guardrail @atl_trust_guardrail ---")

    @atl_trust_guardrail(orchestrator=orchestrator, asset="USDC", value_arg="amount")
    def send_payment(recipient: str, amount: float, reason: str = ""):
        return f"SUCCESS: Sent ${amount} to {recipient}"

    try:
        output = send_payment(
            recipient="0x9999...", amount=250.0, reason="Monthly cloud hosting bill"
        )
        print(f"Function Result: {output}")
    except PermissionError as err:
        print(f"Function Intercepted & Blocked: {err}")

    # 6. Metrics Summary
    print("\n" + "=" * 70)
    print("📊 ATL-Trust Metrics Summary")
    print("=" * 70)
    print(orchestrator.metrics.get_summary())


if __name__ == "__main__":
    main()
