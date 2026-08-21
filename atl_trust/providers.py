import json
import logging
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from .config import ATLTrustConfig
from .models import AgentIntent, GrokDecision, PolicyContext, ToolCall

logger = logging.getLogger("atl_trust.providers")


class BaseLLMProvider(ABC):
    """
    Abstract Base Class for LLM Secondary Intent Judges.
    """
    def __init__(self, config: ATLTrustConfig):
        self.config = config

    def build_prompt(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall],
        policy: PolicyContext,
    ) -> str:
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

    @abstractmethod
    def evaluate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        pass


def handle_failure(config: ATLTrustConfig, error_message: str) -> GrokDecision:
    fail_mode = config.grok_fail_mode
    if fail_mode == "allow":
        return GrokDecision(
            decision="ALLOW",
            confidence=0.0,
            reason=f"LLM API Fallback (Fail-Open): {error_message}",
            drift_detected=False,
            risk_score=0.0,
        )
    elif fail_mode == "require_human":
        return GrokDecision(
            decision="REQUIRE_HUMAN_APPROVAL",
            confidence=0.0,
            reason=f"LLM API Fallback (Escalated to Human): {error_message}",
            drift_detected=True,
            risk_score=0.9,
        )
    elif fail_mode == "rules":
        return GrokDecision(
            decision="ALLOW",
            confidence=0.5,
            reason=f"LLM API Fallback to Pure Rules: {error_message}",
            drift_detected=False,
            risk_score=0.2,
        )
    else:  # Default "deny"
        return GrokDecision(
            decision="DENY",
            confidence=0.0,
            reason=f"LLM API Fallback (Fail-Closed): {error_message}",
            drift_detected=True,
            risk_score=1.0,
        )


class XAIProvider(BaseLLMProvider):
    """xAI Grok-4.6 Secondary Intent Judge"""
    def evaluate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        policy_ctx = policy or PolicyContext()
        prompt = self.build_prompt(intent, tool_call, policy_ctx)
        api_key = self.config.xai_api_key

        if not api_key:
            logger.warning("XAI_API_KEY missing. Triggering fail mode.")
            return handle_failure(
                self.config,
                f"Missing XAI_API_KEY. Fail-mode: {self.config.grok_fail_mode}",
            )

        model = self.config.llm_model or self.config.grok_model or "grok-4.6"
        url = "https://api.x.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are an immutable Zero-Trust Security Sentinel."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
        }

        return _call_json_llm_api(url, headers, payload, self.config)


class OpenAIProvider(BaseLLMProvider):
    """OpenAI GPT-4o Secondary Intent Judge"""
    def evaluate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        policy_ctx = policy or PolicyContext()
        prompt = self.build_prompt(intent, tool_call, policy_ctx)
        api_key = self.config.openai_api_key or self.config.xai_api_key

        if not api_key:
            logger.warning("OPENAI_API_KEY missing. Triggering fail mode.")
            return handle_failure(
                self.config,
                f"Missing OPENAI_API_KEY. Fail-mode: {self.config.grok_fail_mode}",
            )

        model = self.config.llm_model or "gpt-4o"
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are an immutable Zero-Trust Security Sentinel."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        return _call_json_llm_api(url, headers, payload, self.config)


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Claude 3.5 Sonnet Secondary Intent Judge"""
    def evaluate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        policy_ctx = policy or PolicyContext()
        prompt = self.build_prompt(intent, tool_call, policy_ctx)
        api_key = self.config.anthropic_api_key

        if not api_key:
            logger.warning("ANTHROPIC_API_KEY missing. Triggering fail mode.")
            return handle_failure(
                self.config,
                f"Missing ANTHROPIC_API_KEY. Fail-mode: {self.config.grok_fail_mode}",
            )

        model = self.config.llm_model or "claude-3-5-sonnet-20241022"
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
        }

        return _call_anthropic_api(url, headers, payload, self.config)


class OllamaProvider(BaseLLMProvider):
    """Local Ollama / vLLM Secondary Intent Judge"""
    def evaluate(
        self,
        intent: AgentIntent,
        tool_call: Optional[ToolCall] = None,
        policy: Optional[PolicyContext] = None,
    ) -> GrokDecision:
        policy_ctx = policy or PolicyContext()
        prompt = self.build_prompt(intent, tool_call, policy_ctx)
        host = self.config.ollama_host.rstrip('/')
        model = self.config.llm_model or "llama3:70b"

        url = f"{host}/api/generate"
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.config.grok_timeout_seconds) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                raw_text = result.get("response", "{}")
                data = json.loads(raw_text)
                return GrokDecision(
                    decision=data.get("decision", "DENY"),
                    confidence=float(data.get("confidence", 0.5)),
                    reason=f"[Ollama/{model}] {data.get('reason', 'Evaluated')}",
                    drift_detected=bool(data.get("drift_detected", False)),
                    risk_score=float(data.get("risk_score", 0.5)),
                    raw_response=data,
                )
        except Exception as e:
            logger.error(f"Ollama execution error: {e}")
            return handle_failure(
                self.config,
                f"Ollama API error: {str(e)}",
            )


def _call_json_llm_api(url: str, headers: Dict[str, str], payload: Dict[str, Any], config: ATLTrustConfig) -> GrokDecision:
    try:
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=config.grok_timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            clean_text = content.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            data = json.loads(clean_text.strip())
            return GrokDecision(
                decision=data.get("decision", "DENY"),
                confidence=float(data.get("confidence", 0.5)),
                reason=data.get("reason", "Evaluated by LLM Judge"),
                drift_detected=bool(data.get("drift_detected", False)),
                risk_score=float(data.get("risk_score", 0.5)),
                raw_response=body,
            )
    except Exception as e:
        logger.error(f"LLM API Error calling {url}: {e}")
        return handle_failure(
            config,
            f"LLM Provider API error: {str(e)}",
        )


def _call_anthropic_api(url: str, headers: Dict[str, str], payload: Dict[str, Any], config: ATLTrustConfig) -> GrokDecision:
    try:
        req_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=config.grok_timeout_seconds) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["content"][0]["text"]
            clean_text = content.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]
            data = json.loads(clean_text.strip())
            return GrokDecision(
                decision=data.get("decision", "DENY"),
                confidence=float(data.get("confidence", 0.5)),
                reason=data.get("reason", "Evaluated by Claude 3.5 Sonnet"),
                drift_detected=bool(data.get("drift_detected", False)),
                risk_score=float(data.get("risk_score", 0.5)),
                raw_response=body,
            )
    except Exception as e:
        logger.error(f"Anthropic API Error: {e}")
        return handle_failure(
            config,
            f"Anthropic Provider API error: {str(e)}",
        )


def get_provider(config: Optional[ATLTrustConfig] = None) -> BaseLLMProvider:
    cfg = config or ATLTrustConfig.from_env()
    provider_name = cfg.provider.lower()
    if provider_name == "openai":
        return OpenAIProvider(cfg)
    elif provider_name == "anthropic":
        return AnthropicProvider(cfg)
    elif provider_name == "ollama":
        return OllamaProvider(cfg)
    else:
        return XAIProvider(cfg)
