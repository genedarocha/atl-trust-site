import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ValidationMetrics:
    total_calls: int = 0
    grok_calls: int = 0
    rules_calls: int = 0
    hybrid_calls: int = 0
    fallback_calls: int = 0
    decisions: Dict[str, int] = field(default_factory=lambda: {
        "ALLOW": 0,
        "DENY": 0,
        "REQUIRE_HUMAN_APPROVAL": 0,
        "THROTTLE": 0,
        "CIRCUIT_BREAKER_TRIPPED": 0,
    })
    total_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total_calls if self.total_calls > 0 else 0.0

    @property
    def fallback_rate(self) -> float:
        return (self.fallback_calls / self.grok_calls * 100.0) if self.grok_calls > 0 else 0.0


class ValidationMetricsTracker:
    """
    Thread-safe metrics collector for ATL-Trust validator operations.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.metrics = ValidationMetrics()

    def record_validation(
        self,
        validator_used: str,
        decision_code: str,
        latency_ms: float,
        is_fallback: bool = False,
    ):
        with self._lock:
            m = self.metrics
            m.total_calls += 1

            if "grok" in validator_used.lower():
                m.grok_calls += 1
            elif "rules" in validator_used.lower():
                m.rules_calls += 1

            if "hybrid" in validator_used.lower():
                m.hybrid_calls += 1

            if is_fallback:
                m.fallback_calls += 1

            d_key = decision_code.upper()
            m.decisions[d_key] = m.decisions.get(d_key, 0) + 1

            m.total_latency_ms += latency_ms
            if latency_ms > m.max_latency_ms:
                m.max_latency_ms = latency_ms
            if latency_ms < m.min_latency_ms:
                m.min_latency_ms = latency_ms

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            m = self.metrics
            return {
                "total_calls": m.total_calls,
                "grok_calls": m.grok_calls,
                "rules_calls": m.rules_calls,
                "hybrid_calls": m.hybrid_calls,
                "fallback_calls": m.fallback_calls,
                "fallback_rate_pct": round(m.fallback_rate, 2),
                "avg_latency_ms": round(m.avg_latency_ms, 2),
                "max_latency_ms": round(m.max_latency_ms if m.max_latency_ms != 0 else 0.0, 2),
                "min_latency_ms": round(m.min_latency_ms if m.min_latency_ms != float("inf") else 0.0, 2),
                "decision_distribution": dict(m.decisions),
            }

    def reset(self):
        with self._lock:
            self.metrics = ValidationMetrics()
