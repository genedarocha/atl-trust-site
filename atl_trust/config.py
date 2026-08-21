import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ATLTrustConfig:
    validator_mode: str = "rules"  # "rules", "grok", "hybrid"
    provider: str = "xai"  # "xai", "openai", "anthropic", "ollama"
    xai_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    ollama_host: str = "http://localhost:11434"
    llm_model: Optional[str] = None
    grok_model: str = "grok-4.6"
    grok_timeout_seconds: float = 8.0
    grok_fail_mode: str = "deny"  # "deny", "allow", "require_human", "rules"
    atl_trust_core_url: str = "http://localhost:3000"
    
    # Risk threshold for hybrid mode (actions with value > threshold or marked sensitive trigger Grok)
    high_risk_value_threshold: float = 1000.0

    # Idempotency and Bounded Orchestration defaults
    idempotency_ttl_seconds: float = 300.0
    max_steps_per_session: int = 50
    max_cumulative_cost: float = 10.0

    @classmethod
    def from_env(cls) -> "ATLTrustConfig":
        validator_mode = os.getenv("ATL_TRUST_VALIDATOR", "rules").lower()
        if validator_mode not in ("rules", "grok", "hybrid"):
            validator_mode = "rules"

        provider = os.getenv("ATL_TRUST_PROVIDER", "xai").lower()
        if provider not in ("xai", "openai", "anthropic", "ollama"):
            provider = "xai"

        grok_fail_mode = os.getenv("GROK_FAIL_MODE", "deny").lower()
        if grok_fail_mode not in ("deny", "allow", "require_human", "rules"):
            grok_fail_mode = "deny"

        try:
            timeout = float(os.getenv("GROK_TIMEOUT_SECONDS", "8"))
        except ValueError:
            timeout = 8.0

        try:
            risk_threshold = float(os.getenv("HIGH_RISK_VALUE_THRESHOLD", "1000.0"))
        except ValueError:
            risk_threshold = 1000.0

        try:
            idempotency_ttl = float(os.getenv("IDEMPOTENCY_TTL_SECONDS", "300.0"))
        except ValueError:
            idempotency_ttl = 300.0

        try:
            max_steps = int(os.getenv("MAX_STEPS_PER_SESSION", "50"))
        except ValueError:
            max_steps = 50

        try:
            max_cost = float(os.getenv("MAX_CUMULATIVE_COST", "10.0"))
        except ValueError:
            max_cost = 10.0

        return cls(
            validator_mode=validator_mode,
            provider=provider,
            xai_api_key=os.getenv("XAI_API_KEY"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            llm_model=os.getenv("LLM_MODEL"),
            grok_model=os.getenv("GROK_MODEL", "grok-4.6"),
            grok_timeout_seconds=timeout,
            grok_fail_mode=grok_fail_mode,
            atl_trust_core_url=os.getenv("ATL_TRUST_CORE_URL", "http://localhost:3000"),
            high_risk_value_threshold=risk_threshold,
            idempotency_ttl_seconds=idempotency_ttl,
            max_steps_per_session=max_steps,
            max_cumulative_cost=max_cost,
        )

