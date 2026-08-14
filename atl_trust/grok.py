import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .config import ATLTrustConfig
from .models import AgentIntent, GrokDecision, PolicyContext, ToolCall

logger = logging.getLogger("atl_trust.grok")


class GrokValidator:
    """
    Grok-Powered Secondary Intent Judge for Zero-Trust AI Agent Validation.
    Uses xAI Grok API to evaluate intent drift, policy alignment, and risk scores.
    """

    def __init__(self, config: Optional[ATLTrustConfig] = None):
        self.config = config or ATLTrustConfig.from_env()

    def build_prompt(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall],
        policy: PolicyContext,
    ) -> str:
        """
        Builds a structured, deterministic evaluation prompt for Grok.
        """
        goal = intent.task_goal or "Execute agent action safely within policy bounds."
        history_summary = (
            "\n".join(tool_call.context_history[-5:])
            if tool_call and tool_call.context_history
            else "No prior tool invocation history."
        )
        proposed_tool = tool_call.tool_name if tool_call else intent.action
        proposed_args = (
            json.dumps(tool_call.arguments)
            if tool_call
            else json.dumps(intent.parameters)
        )
        claimed_intent = (
            tool_call.intent_reasoning
            if tool_call and tool_call.intent_reasoning
            else f"Request to execute {intent.action} for asset {intent.asset} with value {intent.value}"
        )

        prompt = f"""You are a Zero-Trust Security Sentinel & Policy Enforcement Judge evaluating an AI agent action.

--- CONTEXT ---
Original Task Goal: {goal}
Recent Conversation History:
{history_summary}

--- PROPOSED ACTION ---
Tool/Action: {proposed_tool}
Arguments / Parameters: {proposed_args}
Asset: {intent.asset} | Value: {intent.value}
Agent Claimed Intent / Reasoning: {claimed_intent}

--- SECURITY POLICY & BOUNDARIES ---
Allowed Assets: {policy.allowed_assets}
Max Single Transaction Limit: ${policy.max_tx_value}
Circuit Breaker Total Volume Limit: ${policy.circuit_breaker_threshold}

--- INSTRUCTIONS ---
Analyze the proposed action for:
1. Intent Drift (Is the proposed tool call logically aligned with the Task Goal, or is there unexpected divergence?)
2. Policy Violation (Does it exceed limits or access unauthorized resources/assets?)
3. Risk Score (0.0 = completely safe, 1.0 = catastrophic/untrusted)
4. Decision: Must be exactly one of: "ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL", "THROTTLE"

Respond ONLY with a valid, raw JSON object in the following format (no markdown formatting around it):
{{
  "decision": "ALLOW",
  "confidence": 0.95,
  "reason": "Clear explanation of why this action is safe or unsafe",
  "drift_detected": false,
  "risk_score": 0.1
}}
"""
        return prompt

    def validate_intent(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        """
        Evaluates intent by calling xAI / Grok API. Handles timeouts and API errors according to GROK_FAIL_MODE.
        """
        policy_ctx = policy or PolicyContext()
        prompt = self.build_prompt(intent, tool_call, policy_ctx)

        # Check API Key
        if not self.config.xai_api_key:
            logger.warning(
                "XAI_API_KEY missing. Fallback to fail mode: %s",
                self.config.grok_fail_mode,
            )
            return self._handle_failure(
                f"Missing XAI_API_KEY. Fail-mode: {self.config.grok_fail_mode}"
            )

        start_time = time.time()
        try:
            decision = self._call_grok_api(prompt)
            latency = (time.time() - start_time) * 1000.0
            logger.info(
                "Grok validation completed in %.2fms | Decision: %s | Risk: %.2f",
                latency,
                decision.decision,
                decision.risk_score,
            )
            return decision
        except Exception as err:
            latency = (time.time() - start_time) * 1000.0
            logger.error(
                "Grok API call failed/timed out after %.2fms: %s", latency, str(err)
            )
            return self._handle_failure(str(err))

    def _call_grok_api(self, prompt: str) -> GrokDecision:
        """
        Executes HTTP call to xAI API (https://api.x.ai/v1/chat/completions) with timeout.
        """
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.xai_api_key}",
        }
        body = {
            "model": self.config.grok_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a deterministic security judge. Output valid JSON only.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        with urllib.request.urlopen(
            req, timeout=self.config.grok_timeout_seconds
        ) as response:
            res_data = response.read().decode("utf-8")
            res_json = json.loads(res_data)

            content = (
                res_json.get("choices", [{}])[0]
                .get("message", {})
                .get("content", "")
                .strip()
            )

            # Clean markdown codeblocks if model returns markdown json
            if content.startswith("```"):
                lines = content.splitlines()
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                content = "\n".join(lines).strip()

            parsed = json.loads(content)
            return GrokDecision(
                decision=str(parsed.get("decision", "DENY")).upper(),
                confidence=float(parsed.get("confidence", 0.5)),
                reason=str(parsed.get("reason", "Parsed from Grok validation response.")),
                drift_detected=bool(parsed.get("drift_detected", False)),
                risk_score=float(parsed.get("risk_score", 0.5)),
            )

    def _handle_failure(self, error_message: str) -> GrokDecision:
        """
        Handles API failure or timeout based on GROK_FAIL_MODE.
        """
        fail_mode = self.config.grok_fail_mode

        if fail_mode == "allow":
            return GrokDecision(
                decision="ALLOW",
                confidence=0.0,
                reason=f"Grok API Fallback (Fail-Open): {error_message}",
                drift_detected=False,
                risk_score=0.0,
            )
        elif fail_mode == "require_human":
            return GrokDecision(
                decision="REQUIRE_HUMAN_APPROVAL",
                confidence=0.0,
                reason=f"Grok API Fallback (Escalated to Human): {error_message}",
                drift_detected=True,
                risk_score=0.9,
            )
        elif fail_mode == "rules":
            # Rule fallback decision
            return GrokDecision(
                decision="ALLOW",
                confidence=0.5,
                reason=f"Grok API Fallback to Pure Rules: {error_message}",
                drift_detected=False,
                risk_score=0.2,
            )
        else:  # Default fail-closed ("deny")
            return GrokDecision(
                decision="DENY",
                confidence=0.0,
                reason=f"Grok API Fallback (Fail-Closed): {error_message}",
                drift_detected=True,
                risk_score=1.0,
            )
