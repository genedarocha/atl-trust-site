import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ATLTrustConfig:
    validator_mode: str = "rules"  # "rules", "grok", "hybrid"
    xai_api_key: Optional[str] = None
    grok_model: str = "grok-4.6"
    grok_timeout_seconds: float = 8.0
    grok_fail_mode: str = "deny"  # "deny", "allow", "require_human", "rules"
    atl_trust_core_url: str = "http://localhost:3000"
    
    # Risk threshold for hybrid mode (actions with value > threshold or marked sensitive trigger Grok)
    high_risk_value_threshold: float = 1000.0

    @classmethod
    def from_env(cls) -> "ATLTrustConfig":
        validator_mode = os.getenv("ATL_TRUST_VALIDATOR", "rules").lower()
        if validator_mode not in ("rules", "grok", "hybrid"):
            validator_mode = "rules"

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

        return cls(
            validator_mode=validator_mode,
            xai_api_key=os.getenv("XAI_API_KEY"),
            grok_model=os.getenv("GROK_MODEL", "grok-4.6"),
            grok_timeout_seconds=timeout,
            grok_fail_mode=grok_fail_mode,
            atl_trust_core_url=os.getenv("ATL_TRUST_CORE_URL", "http://localhost:3000"),
            high_risk_value_threshold=risk_threshold,
        )
