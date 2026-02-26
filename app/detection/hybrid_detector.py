from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import load_config
from app.detection.ml_model import MLModel
from app.detection.rules_engine import RulesEngine
from app.features.feature_types import FeatureVector


@dataclass(frozen=True)
class DetectionResult:
    rule_score: float
    ml_score: float
    combined_risk: float
    decision: str
    needs_ai: bool
    guessed_threat_type: str | None
    rule_hits: dict[str, Any]
    ml_model_used: str


class HybridDetector:
    def __init__(self):
        self.cfg = load_config().raw
        self.rules = RulesEngine()
        self.ml = MLModel()

    def detect(self, fv: FeatureVector) -> DetectionResult:
        rule_weight = float(self.cfg["detection"]["rule_weight"])
        ml_weight = float(self.cfg["detection"]["ml_weight"])

        rr = self.rules.evaluate(fv)
        mr = self.ml.score(fv)

        combined = (rule_weight * rr.score) + (ml_weight * mr.score)
        combined = max(0.0, min(1.0, combined))

        block_thr = float(self.cfg["detection"]["block_threshold"])
        alert_thr = float(self.cfg["detection"]["alert_threshold"])
        ai_low = float(self.cfg["detection"]["ai_review_low"])
        ai_high = float(self.cfg["detection"]["ai_review_high"])
        gemini_enabled = bool(self.cfg.get("gemini", {}).get("enabled", False))

        needs_ai = False
        if gemini_enabled and (ai_low <= combined <= ai_high) and rr.score < 0.8:
            needs_ai = True

        if combined >= block_thr:
            decision = "block"
        elif combined >= alert_thr:
            decision = "monitor"
        elif needs_ai:
            decision = "ai_review"
        else:
            decision = "allow"

        return DetectionResult(
            rule_score=rr.score,
            ml_score=mr.score,
            combined_risk=combined,
            decision=decision,
            needs_ai=needs_ai,
            guessed_threat_type=rr.guessed_threat_type,
            rule_hits=rr.hits,
            ml_model_used=mr.model_used,
        )

