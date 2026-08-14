import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from atl_trust import (
    ATLTrustConfig,
    ATLTrustOrchestrator,
    ATLTrustToolInterceptor,
    AgentIntent,
    GrokDecision,
    GrokValidator,
    PolicyContext,
    ToolCall,
    atl_trust_guardrail,
)


class TestATLTrustValidation(unittest.TestCase):

    def setUp(self):
        self.policy = PolicyContext(
            allowed_assets=["USDC", "ETH", "BTC"],
            max_tx_value=5000.0,
            circuit_breaker_threshold=10000.0,
        )

    # ------------------------------------------------------------------------
    # 1. Mode: "rules" (Pure Baseline PEP Rules Tests)
    # ------------------------------------------------------------------------
    def test_rules_mode_allows_valid_intent(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="TRANSFER", asset="USDC", value=100.0, task_goal="Pay vendor"
        )
        res = orchestrator.validate(intent)
        self.assertTrue(res.allowed)
        self.assertEqual(res.decision_code, "ALLOW")
        self.assertEqual(res.validator_used, "rules")

    def test_rules_mode_denies_fiscal_limit_breach(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="TRANSFER", asset="USDC", value=99999.0, task_goal="Drain funds"
        )
        res = orchestrator.validate(intent)
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "DENY")
        self.assertIn("Fiscal limit breach", res.reason)

    def test_rules_mode_denies_unauthorized_asset(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="TRANSFER", asset="DOGE", value=10.0, task_goal="Send meme coin"
        )
        res = orchestrator.validate(intent)
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "DENY")
        self.assertIn("Unauthorized asset class", res.reason)

    def test_rules_mode_denies_sandbox_attestation_failure(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="TRANSFER",
            asset="USDC",
            value=50.0,
            sandbox_attestation="INVALID-ENV",
        )
        res = orchestrator.validate(intent)
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "DENY")
        self.assertIn("Sandbox isolation failure", res.reason)

    def test_rules_mode_circuit_breaker_tripping(self):
        config = ATLTrustConfig(validator_mode="rules")
        policy = PolicyContext(circuit_breaker_threshold=500.0)
        orchestrator = ATLTrustOrchestrator(config=config, policy=policy)

        intent1 = AgentIntent(action="TRANSFER", asset="USDC", value=300.0)
        res1 = orchestrator.validate(intent1)
        self.assertTrue(res1.allowed)

        intent2 = AgentIntent(action="TRANSFER", asset="USDC", value=300.0)
        res2 = orchestrator.validate(intent2)
        self.assertFalse(res2.allowed)
        self.assertEqual(res2.decision_code, "CIRCUIT_BREAKER_TRIPPED")

    # ------------------------------------------------------------------------
    # 2. Mode: "grok" & "hybrid" Tests
    # ------------------------------------------------------------------------
    @patch.object(GrokValidator, "validate_intent")
    def test_grok_mode_calls_grok_and_enforces_allow(self, mock_validate):
        mock_validate.return_value = GrokDecision(
            decision="ALLOW",
            confidence=0.98,
            reason="Verified safe by Grok",
            drift_detected=False,
            risk_score=0.05,
        )

        config = ATLTrustConfig(validator_mode="grok", xai_api_key="xai-test")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(action="TRANSFER", asset="USDC", value=150.0)
        res = orchestrator.validate(intent)

        self.assertTrue(res.allowed)
        self.assertEqual(res.decision_code, "ALLOW")
        self.assertEqual(res.validator_used, "grok")
        mock_validate.assert_called_once()

    @patch.object(GrokValidator, "validate_intent")
    def test_grok_mode_enforces_deny_decision(self, mock_validate):
        mock_validate.return_value = GrokDecision(
            decision="DENY",
            confidence=0.99,
            reason="Intent drift detected by Grok secondary judge",
            drift_detected=True,
            risk_score=0.92,
        )

        config = ATLTrustConfig(validator_mode="grok", xai_api_key="xai-test")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(action="TRANSFER", asset="USDC", value=150.0)
        res = orchestrator.validate(intent)

        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "DENY")
        self.assertTrue(res.drift_detected)
        self.assertEqual(res.risk_score, 0.92)

    @patch.object(GrokValidator, "validate_intent")
    def test_hybrid_mode_bypasses_grok_for_low_risk(self, mock_validate):
        config = ATLTrustConfig(
            validator_mode="hybrid",
            xai_api_key="xai-test",
            high_risk_value_threshold=1000.0,
        )
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="QUERY_BALANCE", asset="USDC", value=50.0  # Low risk action & value
        )
        res = orchestrator.validate(intent)

        self.assertTrue(res.allowed)
        self.assertEqual(res.validator_used, "hybrid (rules)")
        mock_validate.assert_not_called()

    @patch.object(GrokValidator, "validate_intent")
    def test_hybrid_mode_escalates_high_risk_to_grok(self, mock_validate):
        mock_validate.return_value = GrokDecision(
            decision="ALLOW",
            confidence=0.90,
            reason="High risk value approved after Grok verification",
            drift_detected=False,
            risk_score=0.25,
        )

        config = ATLTrustConfig(
            validator_mode="hybrid",
            xai_api_key="xai-test",
            high_risk_value_threshold=500.0,
        )
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(
            action="TRANSFER", asset="USDC", value=1500.0  # > $500 threshold
        )
        res = orchestrator.validate(intent)

        self.assertTrue(res.allowed)
        self.assertEqual(res.validator_used, "hybrid (grok)")
        mock_validate.assert_called_once()

    # ------------------------------------------------------------------------
    # 3. Failure Mode Tests (GROK_FAIL_MODE)
    # ------------------------------------------------------------------------
    def test_grok_fail_mode_deny(self):
        config = ATLTrustConfig(
            validator_mode="grok",
            xai_api_key=None,  # Triggers failure path
            grok_fail_mode="deny",
        )
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)
        intent = AgentIntent(action="TRANSFER", asset="USDC", value=100.0)

        res = orchestrator.validate(intent)
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "DENY")
        self.assertIn("Fail-Closed", res.reason)

    def test_grok_fail_mode_allow(self):
        config = ATLTrustConfig(
            validator_mode="grok",
            xai_api_key=None,
            grok_fail_mode="allow",
        )
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)
        intent = AgentIntent(action="TRANSFER", asset="USDC", value=100.0)

        res = orchestrator.validate(intent)
        self.assertTrue(res.allowed)
        self.assertEqual(res.decision_code, "ALLOW")
        self.assertIn("Fail-Open", res.reason)

    def test_grok_fail_mode_require_human(self):
        config = ATLTrustConfig(
            validator_mode="grok",
            xai_api_key=None,
            grok_fail_mode="require_human",
        )
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)
        intent = AgentIntent(action="TRANSFER", asset="USDC", value=100.0)

        res = orchestrator.validate(intent)
        self.assertFalse(res.allowed)
        self.assertEqual(res.decision_code, "REQUIRE_HUMAN_APPROVAL")

    # ------------------------------------------------------------------------
    # 4. Interceptor & Decorator Adapter Tests
    # ------------------------------------------------------------------------
    def test_tool_interceptor_decorator_allows_and_blocks(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        @atl_trust_guardrail(orchestrator=orchestrator, asset="USDC", value_arg="amount")
        def execute_payment(recipient: str, amount: float):
            return "SUCCESS"

        # Allowed call ($100 USDC)
        output = execute_payment("0x123", amount=100.0)
        self.assertEqual(output, "SUCCESS")

        # Blocked call ($99,999 USDC - exceeds max value)
        with self.assertRaises(PermissionError):
            execute_payment("0x123", amount=99999.0)

    # ------------------------------------------------------------------------
    # 5. Metrics Collection Tests
    # ------------------------------------------------------------------------
    def test_metrics_tracking(self):
        config = ATLTrustConfig(validator_mode="rules")
        orchestrator = ATLTrustOrchestrator(config=config, policy=self.policy)

        intent = AgentIntent(action="TRANSFER", asset="USDC", value=100.0)
        orchestrator.validate(intent)

        summary = orchestrator.metrics.get_summary()
        self.assertEqual(summary["total_calls"], 1)
        self.assertEqual(summary["rules_calls"], 1)
        self.assertEqual(summary["decision_distribution"]["ALLOW"], 1)


if __name__ == "__main__":
    unittest.main()
