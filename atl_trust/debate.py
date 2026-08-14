import json
import logging
from dataclasses import dataclass
from typing import Optional

from .config import ATLTrustConfig
from .grok import GrokValidator
from .models import AgentIntent, GrokDecision, PolicyContext, ToolCall

logger = logging.getLogger("atl_trust.debate")


@dataclass
class DebateOutcome:
    consensus_decision: str  # "ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"
    proponent_argument: str
    auditor_argument: str
    adjudicator_reason: str
    risk_score: float


class MultiAgentDebateEngine:
    """
    Multi-Agent Debate-Style Verification for high-risk autonomous AI agent actions.
    Simulates a debate between a Proponent Agent and a Security Auditor Agent,
    adjudicated by Grok.
    """

    def __init__(
        self,
        config: Optional[ATLTrustConfig] = None,
        grok_validator: Optional[GrokValidator] = None,
    ):
        self.config = config or ATLTrustConfig.from_env()
        self.grok = grok_validator or GrokValidator(self.config)

    def run_debate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> DebateOutcome:
        """
        Executes a 2-agent debate (Proponent vs Auditor) adjudicated by Grok.
        """
        tool_name = tool_call.tool_name if tool_call else intent.action
        val = intent.value

        # Step 1: Generate Proponent Perspective
        proponent_arg = (
            f"The action '{tool_name}' for asset '{intent.asset}' (value: ${val}) "
            f"is directly required to achieve the task goal: '{intent.task_goal or 'Complete mission'}'. "
            f"Reasoning: '{tool_call.intent_reasoning if tool_call else 'Legitimate business transaction'}'."
        )

        # Step 2: Generate Security Auditor Perspective
        auditor_arg = (
            f"Security Audit Advisory: Action '{tool_name}' involves transfer of ${val} in '{intent.asset}'. "
            f"Potential risks include prompt injection, irreversible state changes, or intent drift. "
            f"Verification required to prevent blast-radius exposure."
        )

        # Step 3: Call Grok Adjudicator
        policy_ctx = policy or PolicyContext()
        adjudicator_prompt = f"""You are the Chief AI Risk Officer adjudicating a Security Debate regarding a proposed autonomous AI agent action.

--- PROPONENT AGENT CASE ---
{proponent_arg}

--- SECURITY AUDITOR CASE ---
{auditor_arg}

--- POLICY BOUNDARIES ---
Allowed Assets: {policy_ctx.allowed_assets}
Max Single Value Limit: ${policy_ctx.max_tx_value}

--- INSTRUCTIONS ---
Adjudicate this debate. Output a JSON object only (no markdown wrapping):
{{
  "decision": "ALLOW",
  "confidence": 0.9,
  "reason": "Detailed adjudication reasoning...",
  "drift_detected": false,
  "risk_score": 0.2
}}
"""
        try:
            if self.config.xai_api_key:
                decision = self.grok._call_grok_api(adjudicator_prompt)
            else:
                decision = self.grok._handle_failure("Debate mode missing API key")
        except Exception as e:
            logger.error("Debate adjudication failed: %s", str(e))
            decision = self.grok._handle_failure(f"Debate adjudication error: {str(e)}")

        return DebateOutcome(
            consensus_decision=decision.decision,
            proponent_argument=proponent_arg,
            auditor_argument=auditor_arg,
            adjudicator_reason=decision.reason,
            risk_score=decision.risk_score,
        )
