import functools
import logging
from typing import Any, Callable, Dict, Optional

from .config import ATLTrustConfig
from .models import AgentIntent, ToolCall, ValidationResult
from .validator import ATLTrustOrchestrator

logger = logging.getLogger("atl_trust.adapter")


class ATLTrustToolInterceptor:
    """
    Interceptor & Middleware for routing agent tool calls through ATL-Trust Zero-Trust Proxy.
    Compatible with LangGraph, CrewAI, AutoGen, and custom Python agents.
    """

    def __init__(self, orchestrator: Optional[ATLTrustOrchestrator] = None):
        self.orchestrator = orchestrator or ATLTrustOrchestrator()

    def intercept_and_validate(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        intent_reasoning: str = "",
        asset: str = "USDC",
        value: float = 0.0,
        task_goal: str = "",
        context_history: Optional[list] = None,
    ) -> ValidationResult:
        """
        Intercepts a proposed tool call, constructs the AgentIntent and ToolCall objects,
        and runs them through ATL-Trust PEP + Grok validation.
        """
        intent = AgentIntent(
            action=tool_name,
            asset=asset,
            value=value,
            task_goal=task_goal,
            parameters=arguments,
        )

        tool_call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            intent_reasoning=intent_reasoning,
            context_history=context_history or [],
        )

        result = self.orchestrator.validate(intent, tool_call)
        if not result.allowed:
            logger.warning(
                "🚨 TOOL CALL BLOCKED by ATL-Trust [%s]: %s | Reason: %s",
                result.validator_used,
                tool_name,
                result.reason,
            )
        else:
            logger.info(
                "✅ TOOL CALL ALLOWED by ATL-Trust [%s]: %s",
                result.validator_used,
                tool_name,
            )
        return result

    def wrap_tool(self, tool_func: Callable) -> Callable:
        """
        Wraps a function/tool so that it is automatically validated before execution.
        """
        @functools.wraps(tool_func)
        def wrapper(*args, **kwargs):
            tool_name = tool_func.__name__
            val = kwargs.get("amount", kwargs.get("value", 0.0))
            asset = kwargs.get("asset", "USDC")
            intent_reasoning = kwargs.get("reason", f"Execution of {tool_name}")

            res = self.intercept_and_validate(
                tool_name=tool_name,
                arguments=kwargs or {"args": args},
                intent_reasoning=intent_reasoning,
                asset=asset,
                value=val,
            )

            if not res.allowed:
                raise PermissionError(
                    f"ATL-Trust Security Rejection [{res.decision_code} via {res.validator_used}]: {res.reason}"
                )

            return tool_func(*args, **kwargs)

        return wrapper


def atl_trust_guardrail(
    orchestrator: Optional[ATLTrustOrchestrator] = None,
    asset: str = "USDC",
    value_arg: str = "amount",
):
    """
    Decorator to wrap any Python tool call with ATL-Trust Zero-Trust validation.
    """
    def decorator(func: Callable):
        interceptor = ATLTrustToolInterceptor(orchestrator)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            tool_name = func.__name__
            val = float(kwargs.get(value_arg, 0.0))
            intent_reasoning = kwargs.get("reason", f"Execution of {tool_name}")

            res = interceptor.intercept_and_validate(
                tool_name=tool_name,
                arguments=kwargs or {"args": args},
                intent_reasoning=intent_reasoning,
                asset=asset,
                value=val,
            )

            if not res.allowed:
                raise PermissionError(
                    f"ATL-Trust Security Rejection [{res.decision_code} via {res.validator_used}]: {res.reason}"
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator
