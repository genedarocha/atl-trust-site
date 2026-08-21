from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ValidationMode(str, Enum):
    RULES = "rules"
    GROK = "grok"
    HYBRID = "hybrid"


class FailMode(str, Enum):
    DENY = "deny"
    ALLOW = "allow"
    REQUIRE_HUMAN = "require_human"
    RULES = "rules"


class DecisionCode(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    THROTTLE = "THROTTLE"
    CIRCUIT_BREAKER_TRIPPED = "CIRCUIT_BREAKER_TRIPPED"
    BOUNDED_ORCHESTRATION_BREACH = "BOUNDED_ORCHESTRATION_BREACH"
    IDEMPOTENT_CACHE_HIT = "IDEMPOTENT_CACHE_HIT"


@dataclass
class PolicyContext:
    allowed_assets: List[str] = field(default_factory=lambda: ["USDC", "ETH", "BTC"])
    max_tx_value: float = 5000.0
    circuit_breaker_threshold: float = 10000.0
    require_debate_for_high_risk: bool = False
    max_steps_per_session: int = 50
    max_cumulative_cost: float = 10.0


@dataclass
class ToolCall:
    tool_name: str
    arguments: Dict[str, Any]
    intent_reasoning: str
    context_history: List[str] = field(default_factory=list)
    idempotency_key: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class AgentIntent:
    action: str
    asset: str
    value: float
    semantic_hash: str = "hash_default"
    sandbox_attestation: str = "SANDBOX-ACTIVE-001"
    agent_id: str = "agent-main"
    task_goal: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    idempotency_key: Optional[str] = None
    session_id: str = "default_session"
    step_count: int = 1
    estimated_cost: float = 0.0


@dataclass
class GrokDecision:
    decision: str  # "ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL", "THROTTLE"
    confidence: float
    reason: str
    drift_detected: bool
    risk_score: float  # 0.0 (safe) to 1.0 (extreme risk)


@dataclass
class ValidationResult:
    allowed: bool
    decision_code: str
    validator_used: str  # "rules", "grok", "hybrid (rules)", "hybrid (grok)", "idempotency_cache"
    reason: str
    risk_score: float = 0.0
    grok_decision: Optional[GrokDecision] = None
    execution_time_ms: float = 0.0
    drift_detected: bool = False
    is_cached: bool = False
    session_steps: int = 1

