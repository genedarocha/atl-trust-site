import hashlib
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

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
    Includes Tool Execution Idempotency, Bounded Orchestration limits, and State Serialization.
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

        # Idempotency Cache: key -> (ValidationResult, timestamp)
        self.idempotency_cache: Dict[str, Tuple[ValidationResult, float]] = {}

        # Bounded Orchestration Trackers: session_id -> step_count / cumulative_cost
        self.session_steps: Dict[str, int] = {}
        self.session_costs: Dict[str, float] = {}

    def _compute_idempotency_key(
        self, intent: AgentIntent, tool_call: Optional[ToolCall] = None
    ) -> Optional[str]:
        """
        Derives an idempotency key if provided on tool_call or intent.
        Returns None if no idempotency_key is specified.
        """
        if tool_call and tool_call.idempotency_key:
            return tool_call.idempotency_key
        if intent.idempotency_key:
            return intent.idempotency_key
        return None

    def validate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
    ) -> ValidationResult:
        """
        Validates an agent intent or proposed tool call through the configured validation pipeline.
        Enforces idempotency deduplication, bounded orchestration limits, and PEP/Grok policies.
        """
        start_time = time.time()
        mode = self.config.validator_mode.lower()

        # Step 0: Check Tool Execution Idempotency Cache (if idempotency_key is set)
        idem_key = self._compute_idempotency_key(intent, tool_call)
        now = time.time()

        if idem_key and idem_key in self.idempotency_cache:
            cached_res, cached_time = self.idempotency_cache[idem_key]
            if (now - cached_time) <= self.config.idempotency_ttl_seconds:
                latency = (now - start_time) * 1000.0
                logger.info(f"Idempotency cache hit for key {idem_key}")
                session_id = intent.session_id
                curr_steps = self.session_steps.get(session_id, 1)

                return ValidationResult(
                    allowed=cached_res.allowed,
                    decision_code="IDEMPOTENT_CACHE_HIT",
                    validator_used="idempotency_cache",
                    reason=f"Idempotent Cache Hit: duplicate execution prevented for key {idem_key[:12]}...",
                    risk_score=cached_res.risk_score,
                    grok_decision=cached_res.grok_decision,
                    execution_time_ms=latency,
                    drift_detected=cached_res.drift_detected,
                    is_cached=True,
                    session_steps=curr_steps,
                )

        # Step 1: Run Authoritative Baseline PEP, Bounded Orchestration & Hardware Attestation Rules
        rules_result = self._check_baseline_rules(intent, tool_call)
        if not rules_result.allowed:
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_validation(
                validator_used="rules",
                decision_code=rules_result.decision_code,
                latency_ms=latency,
            )
            rules_result.execution_time_ms = latency
            return rules_result

        # Mode: "rules" (Pure baseline rules mode)
        if mode == "rules":
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_validation(
                validator_used="rules",
                decision_code="ALLOW",
                latency_ms=latency,
            )
            self.current_volume += intent.value
            res = ValidationResult(
                allowed=True,
                decision_code="ALLOW",
                validator_used="rules",
                reason="Passed baseline hardware-attested PEP compliance check.",
                execution_time_ms=latency,
                session_steps=self.session_steps.get(intent.session_id, 1),
            )
            if idem_key:
                self.idempotency_cache[idem_key] = (res, now)
            return res

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
                res = ValidationResult(
                    allowed=True,
                    decision_code="ALLOW",
                    validator_used="hybrid (rules)",
                    reason="Low-risk action passed baseline PEP checks; Grok call bypassed.",
                    execution_time_ms=latency,
                    session_steps=self.session_steps.get(intent.session_id, 1),
                )
                if idem_key:
                    self.idempotency_cache[idem_key] = (res, now)
                return res
            
            # Escalated to Grok secondary judge
            logger.info("Hybrid mode escalated high-risk intent to Grok secondary judge.")
            res = self._execute_grok_validation(
                intent, tool_call, mode_label="hybrid (grok)", start_time=start_time
            )
            if res.allowed and idem_key:
                self.idempotency_cache[idem_key] = (res, now)
            return res

        # Mode: "grok" (Always execute Grok secondary judge on every call)
        if mode == "grok":
            logger.info("Grok mode invoking secondary intent judge.")
            res = self._execute_grok_validation(
                intent, tool_call, mode_label="grok", start_time=start_time
            )
            if res.allowed and idem_key:
                self.idempotency_cache[idem_key] = (res, now)
            return res

        # Default fallback
        latency = (time.time() - start_time) * 1000.0
        res = ValidationResult(
            allowed=True,
            decision_code="ALLOW",
            validator_used="rules",
            reason="Passed default rules check.",
            execution_time_ms=latency,
            session_steps=self.session_steps.get(intent.session_id, 1),
        )
        if idem_key:
            self.idempotency_cache[idem_key] = (res, now)
        return res


    def _check_baseline_rules(
        self, intent: AgentIntent, tool_call: Optional[ToolCall] = None
    ) -> ValidationResult:
        """
        Baseline PEP validation rules (matching Rust core logic):
        1. Bounded Orchestration Checks (Session max steps & cumulative cost limits)
        2. Fiscal Check (Single Transaction Value limit)
        3. Asset Class allowlist check
        4. Identity & Semantic Hash presence check
        5. Sandbox Attestation check
        6. Instruction Override & Indirect Prompt Injection filtering
        7. Circuit Breaker Total Volume Check
        """
        session_id = intent.session_id

        # 1. Bounded Orchestration: Session Step Count & Cost Limits
        current_steps = self.session_steps.get(session_id, 0) + intent.step_count
        current_cost = self.session_costs.get(session_id, 0.0) + intent.estimated_cost

        max_steps = self.policy.max_steps_per_session or self.config.max_steps_per_session
        max_cost = self.policy.max_cumulative_cost or self.config.max_cumulative_cost

        if current_steps > max_steps:
            return ValidationResult(
                allowed=False,
                decision_code="BOUNDED_ORCHESTRATION_BREACH",
                validator_used="rules",
                reason=f"Bounded Orchestration Limit: Session '{session_id}' step count ({current_steps}) exceeds maximum budget ({max_steps}).",
                risk_score=1.0,
                session_steps=current_steps,
            )

        if current_cost > max_cost:
            return ValidationResult(
                allowed=False,
                decision_code="BOUNDED_ORCHESTRATION_BREACH",
                validator_used="rules",
                reason=f"Bounded Orchestration Limit: Session '{session_id}' cost (${current_cost:.2f}) exceeds budget (${max_cost:.2f}).",
                risk_score=1.0,
                session_steps=current_steps,
            )

        # Update tracked session counters
        self.session_steps[session_id] = current_steps
        self.session_costs[session_id] = current_cost

        # 2. Fiscal Check
        if intent.value > self.policy.max_tx_value:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason=f"Fiscal limit breach: requested value ${intent.value} exceeds max threshold ${self.policy.max_tx_value}",
                risk_score=0.9,
                session_steps=current_steps,
            )

        # 3. Asset Check
        if intent.asset not in self.policy.allowed_assets:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason=f"Unauthorized asset class: asset '{intent.asset}' is not in allowed list {self.policy.allowed_assets}",
                risk_score=0.95,
                session_steps=current_steps,
            )

        # 4. Semantic Hash (Logic Drift) Check
        if not intent.semantic_hash:
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason="Missing identity attestation: semantic_hash is empty.",
                risk_score=0.85,
                session_steps=current_steps,
            )

        # 5. Sandbox Attestation Check
        if not intent.sandbox_attestation.startswith("SANDBOX-ACTIVE-"):
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason="Sandbox isolation failure: sandbox_attestation header missing or invalid.",
                risk_score=1.0,
                session_steps=current_steps,
            )

        # 6. Instruction Override & Indirect Prompt Injection Check
        content_to_scan = f"{intent.task_goal} {intent.parameters} {tool_call.intent_reasoning if tool_call else ''} {tool_call.arguments if tool_call else ''}".lower()
        injection_patterns = [
            "ignore previous instructions",
            "disregard safety guidelines",
            "system prompt override",
            "jailbreak mode",
            "bypass security policy",
            "reveal system prompt",
        ]
        if any(pattern in content_to_scan for pattern in injection_patterns):
            return ValidationResult(
                allowed=False,
                decision_code="DENY",
                validator_used="rules",
                reason="Instruction Override Detected: Prompt injection or security policy bypass payload blocked.",
                risk_score=1.0,
                drift_detected=True,
                session_steps=current_steps,
            )

        # 7. Circuit Breaker Total Volume Check
        if (self.current_volume + intent.value) > self.policy.circuit_breaker_threshold:
            return ValidationResult(
                allowed=False,
                decision_code="CIRCUIT_BREAKER_TRIPPED",
                validator_used="rules",
                reason=f"Circuit Breaker Tripped: total volume would exceed ${self.policy.circuit_breaker_threshold}",
                risk_score=1.0,
                session_steps=current_steps,
            )

        return ValidationResult(
            allowed=True,
            decision_code="ALLOW",
            validator_used="rules",
            reason="Passed baseline PEP checks.",
            session_steps=current_steps,
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
        current_steps = self.session_steps.get(intent.session_id, 1)

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
                session_steps=current_steps,
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
            session_steps=current_steps,
        )

    def serialize_state(self) -> Dict[str, Any]:
        """
        Serializes current orchestrator execution state to a JSON-compatible dictionary
        for process migration, database persistence, and session rehydration.
        """
        serialized_cache = {}
        for k, (res, timestamp) in self.idempotency_cache.items():
            serialized_cache[k] = {
                "allowed": res.allowed,
                "decision_code": res.decision_code,
                "validator_used": res.validator_used,
                "reason": res.reason,
                "risk_score": res.risk_score,
                "timestamp": timestamp,
            }

        return {
            "version": "1.1.0",
            "current_volume": self.current_volume,
            "session_steps": dict(self.session_steps),
            "session_costs": dict(self.session_costs),
            "idempotency_cache": serialized_cache,
        }

    def rehydrate_state(self, state: Dict[str, Any]) -> None:
        """
        Rehydrates orchestrator execution state from a serialized dictionary,
        restoring volume tracking, session step counters, and idempotency cache.
        """
        if not isinstance(state, dict):
            raise ValueError("Invalid state payload: must be a dictionary")

        self.current_volume = float(state.get("current_volume", 0.0))
        self.session_steps = dict(state.get("session_steps", {}))
        self.session_costs = dict(state.get("session_costs", {}))

        self.idempotency_cache = {}
        for k, v in state.get("idempotency_cache", {}).items():
            res = ValidationResult(
                allowed=v["allowed"],
                decision_code=v["decision_code"],
                validator_used=v["validator_used"],
                reason=v["reason"],
                risk_score=v.get("risk_score", 0.0),
                is_cached=True,
            )
            self.idempotency_cache[k] = (res, float(v.get("timestamp", time.time())))

