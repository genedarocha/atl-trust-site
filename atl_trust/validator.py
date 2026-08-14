import logging
import time
import urllib.error
import urllib.request
import json
from typing import Optional

from .config import ATLTrustConfig
from .debate import MultiAgentDebateEngine
from .grok import GrokValidator
from .metrics import ValidationMetricsTracker
from .models import (
    AgentIntent,
    GrokDecision,
    PolicyContext,
    ToolCall,
    ValidationResult,
)

logger = logging.getLogger("atl_trust.orchestrator")


class ATLTrustOrchestrator:
    """
    Grok-Powered Zero-Trust AI Agent Validation Orchestrator.
    Manages three operational modes: "rules" (default), "grok", and "hybrid".
    """

    def __init__(
        self,
        config: Optional[ATLTrustConfig] = None,
        policy: Optional[PolicyContext] = None,
        grok_validator: Optional[GrokValidator] = None,
    ):
        self.config = config or ATLTrustConfig.from_env()
        self.policy = policy or PolicyContext()
        self.grok = grok_validator or GrokValidator(self.config)
        self.debate_engine = MultiAgentDebateEngine(self.config, self.grok)
        self.metrics = ValidationMetricsTracker()
        
        # Track local circuit breaker volume in memory
        self.current_volume: float = 0.0

    def validate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
    ) -> ValidationResult:
        """
        Validates an agent intent or proposed tool call through the configured validation pipeline.
        """
        start_time = time.time()
        mode = self.config.validator_mode.lower()

        # Step 1: Run Authoritative Baseline PEP & Hardware Attestation Rules
        rules_result = self._check_baseline_rules(intent)
        if not rules_result.allowed:
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_validation(
                validator_used="rules",
                decision_code=rules_result.decision_code,
                latency_ms=latency,
            )
            rules_result.execution_time_ms = latency
            return rules_result

        # Mode: "rules" (Pure baseline rules mode - 100% legacy/baseline behavior)
        if mode == "rules":
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_validation(
                validator_used="rules",
                decision_code="ALLOW",
                latency_ms=latency,
            )
            # Update circuit breaker volume on approval
            self.current_volume += intent.value
            return ValidationResult(
                allowed=True,
                decision_code="ALLOW",
                validator_used="rules",
                reason="Passed baseline hardware-attested PEP compliance check.",
                execution_time_ms=latency,
            )

        # Mode: "hybrid" (Rules first, Grok only on high-risk / uncertain actions)
        if mode == "hybrid":
            is_high_risk = self._is_high_risk_call(intent, tool_call)
            if not is_high_risk:
                latency = (time.time() - start_time) * 1000.0
                self.metrics.record_validation(
                    validator_used="hybrid (rules)",
                    decision_code="ALLOW",
                    latency_ms=latency,
                )
                self.current_volume += intent.value
                return ValidationResult(
                    allowed=True,
                    decision_code="ALLOW",
                    validator_used="hybrid (rules)",
                    reason="Low-risk action passed baseline PEP checks; Grok call bypassed.",
                    execution_time_ms=latency,
                )
            
            # Escalated to Grok secondary judge
            logger.info("Hybrid mode escalated high-risk intent to Grok secondary judge.")
            return self._execute_grok_validation(
                intent, tool_call, mode_label="hybrid (grok)", start_time=start_time
            )

        # Mode: "grok" (Always execute Grok secondary judge on every call)
        if mode == "grok":
            logger.info("Grok mode invoking secondary intent judge.")
            return self._execute_grok_validation(
                intent, tool_call, mode_label="grok", start_time=start_time
            )

        # Default fallback
        latency = (time.time() - start_time) * 1000.0
        return ValidationResult(
            allowed=True,
            decision_code="ALLOW",
            validator_used="rules",
            reason="Passed default rules check.",
            execution_time_ms=latency,
        )

    def _check_baseline_rules(self, intent: AgentIntent) -> ValidationResult:
        """
        Baseline PEP validation rules (matching Rust core logic):
        1. Single Transaction Value limit check (Fiscal Check)
        2. Asset Class allowlist check
        3. Semantic Hash presence (Intent Drift baseline)
        4. Hardware / Sandbox Attestation check
        5. Circuit Breaker Total Volume Check
        """
        # Fiscal Check
        if intent.value > self.policy.max_tx_value:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason=f"Fiscal limit breach: requested value ${intent.value} exceeds max threshold ${self.policy.max_tx_value}",
                risk_score=0.9,
            )

        # Asset Check
        if intent.asset not in self.policy.allowed_assets:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason=f"Unauthorized asset class: asset '{intent.asset}' is not in allowed list {self.policy.allowed_assets}",
                risk_score=0.95,
            )

        # Semantic Hash (Logic Drift) Check
        if not intent.semantic_hash:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason="Missing identity attestation: semantic_hash is empty.",
                risk_score=0.85,
            )

        # Sandbox Attestation Check
        if not intent.sandbox_attestation.startswith("SANDBOX-ACTIVE-"):
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason="Sandbox isolation failure: sandbox_attestation header missing or invalid.",
                risk_score=1.0,
            )

        # Circuit Breaker Total Volume Check
        if (self.current_volume + intent.value) > self.policy.circuit_breaker_threshold:
            return ValidationResult(
                allowed=False,
                decision_code="CIRCUIT_BREAKER_TRIPPED",
                validator_used="rules",
                reason=f"Circuit Breaker Tripped: total volume would exceed ${self.policy.circuit_breaker_threshold}",
                risk_score=1.0,
            )

        return ValidationResult(
            allowed=True,
            decision_code="ALLOW",
            validator_used="rules",
            reason="Passed baseline PEP checks.",
        )

    def _is_high_risk_call(
        self, intent: AgentIntent, tool_call: Optional[ToolCall]
    ) -> bool:
        """
        Determines whether a tool call is high-risk/uncertain and requires Grok evaluation.
        """
        # Value exceeds high risk threshold
        if intent.value >= self.config.high_risk_value_threshold:
            return True

        # Sensitive actions
        sensitive_actions = {
            "TRANSFER",
            "SWAP",
            "WITHDRAW",
            "DELETE",
            "EXECUTE_CODE",
            "PAYMENT",
            "SEND_EMAIL",
        }
        action_name = (tool_call.tool_name if tool_call else intent.action).upper()
        if action_name in sensitive_actions:
            return True

        # High risk flags in parameters
        params_str = str(tool_call.arguments if tool_call else intent.parameters).lower()
        if any(term in params_str for term in ["admin", "root", "secret", "private_key", "override"]):
            return True

        return False

    def _execute_grok_validation(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall],
        mode_label: str,
        start_time: float,
    ) -> ValidationResult:
        """
        Executes Grok secondary intent validation (or multi-agent debate if configured).
        """
        if self.policy.require_debate_for_high_risk and self._is_high_risk_call(intent, tool_call):
            debate = self.debate_engine.run_debate(intent, tool_call, self.policy)
            latency = (time.time() - start_time) * 1000.0
            allowed = debate.consensus_decision == "ALLOW"
            
            self.metrics.record_validation(
                validator_used=f"{mode_label} (debate)",
                decision_code=debate.consensus_decision,
                latency_ms=latency,
            )
            if allowed:
                self.current_volume += intent.value

            return ValidationResult(
                allowed=allowed,
                decision_code=debate.consensus_decision,
                validator_used=f"{mode_label} (debate)",
                reason=f"Debate Adjudication: {debate.adjudicator_reason}",
                risk_score=debate.risk_score,
                execution_time_ms=latency,
            )

        # Standard Grok Validation Call
        grok_dec: GrokDecision = self.grok.validate_intent(intent, tool_call, self.policy)
        latency = (time.time() - start_time) * 1000.0
        
        is_fallback = "Fallback" in grok_dec.reason
        allowed = grok_dec.decision == "ALLOW"

        self.metrics.record_validation(
            validator_used=mode_label,
            decision_code=grok_dec.decision,
            latency_ms=latency,
            is_fallback=is_fallback,
        )

        if allowed:
            self.current_volume += intent.value

        return ValidationResult(
            allowed=allowed,
            decision_code=grok_dec.decision,
            validator_used=mode_label,
            reason=grok_dec.reason,
            risk_score=grok_dec.risk_score,
            grok_decision=grok_dec,
            execution_time_ms=latency,
            drift_detected=grok_dec.drift_detected,
        )
