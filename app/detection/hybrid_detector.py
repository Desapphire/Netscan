from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.config import load_config
from app.detection.ml_model import MLModel
from app.detection.rules_engine import RulesEngine
from app.features.feature_types import FeatureVector

logger = logging.getLogger("netscan.detector")


@dataclass(frozen=True)
class DetectionResult:
    rule_score: float
    ml_score: float
    ml_confidence: float          # how certain the ML model is (0–1)
    combined_risk: float
    decision: str
    needs_ai: bool
    guessed_threat_type: str | None
    rule_hits: dict[str, Any]
    correlation_hits: dict[str, Any]
    ml_model_used: str
    top_features: list[tuple[str, float]] = field(default_factory=list)
    boosted: bool = False         # True if risk-boosting was applied


class HybridDetector:
    def __init__(self):
        self.cfg   = load_config().raw
        self.rules = RulesEngine()
        self.ml    = MLModel()

    def detect(self, fv: FeatureVector, session=None) -> DetectionResult:
        """
        Compute a combined risk score.

        session — optional SQLAlchemy session; if provided, risk boosting
                  queries recent detection history for this src_ip.
        """
        det_cfg     = self.cfg["detection"]
        rule_weight = float(det_cfg["rule_weight"])
        ml_weight   = float(det_cfg["ml_weight"])

        rr = self.rules.evaluate(fv)
        mr = self.ml.score(fv)

        combined = float(rule_weight * rr.score + ml_weight * mr.score)
        combined = max(0.0, min(1.0, combined))

        # ── Risk Boosting ──────────────────────────────────────────────────
        boosted  = False
        boost_cfg = self._boost_cfg()
        if boost_cfg.get("repeated_detection_boost", {}).get("enabled") and session is not None:
            combined, boosted = self._apply_boost(combined, fv.src_ip, session, boost_cfg, rr)

        # Also boost if multiple distinct threat types appeared in one window
        mt_cfg = boost_cfg.get("multi_threat_type_boost", {})
        if mt_cfg.get("enabled") and not boosted:
            threat_types = {
                h.get("description", "").split()[0]
                for h in rr.hits.values()
                if isinstance(h, dict)
            }
            if len(threat_types) >= int(mt_cfg.get("min_threat_types", 2)):
                mult = float(mt_cfg.get("multiplier", 1.15))
                combined = min(1.0, combined * mult)
                boosted = True

        # ── Decision ──────────────────────────────────────────────────────
        block_thr  = float(det_cfg["block_threshold"])
        alert_thr  = float(det_cfg["alert_threshold"])
        ai_low     = float(det_cfg["ai_review_low"])
        ai_high    = float(det_cfg["ai_review_high"])
        gemini_on  = bool(self.cfg.get("gemini", {}).get("enabled", False))

        needs_ai = gemini_on and (ai_low <= combined <= ai_high) and rr.score < 0.8

        if combined >= block_thr:
            decision = "block"
        elif combined >= alert_thr:
            decision = "monitor"
        elif needs_ai:
            decision = "ai_review"
        else:
            decision = "allow"

        if mr.drift_detected:
            logger.warning(
                "⚠ DRIFT on %s — top anomaly features: %s",
                fv.src_ip,
                ", ".join(f"{n}={v:.2f}" for n, v in mr.top_features),
            )

        return DetectionResult(
            rule_score=rr.score,
            ml_score=mr.score,
            ml_confidence=mr.confidence,
            combined_risk=combined,
            decision=decision,
            needs_ai=needs_ai,
            guessed_threat_type=rr.guessed_threat_type,
            rule_hits=rr.hits,
            correlation_hits=rr.correlation_hits,
            ml_model_used=mr.model_used,
            top_features=mr.top_features,
            boosted=boosted,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _boost_cfg(self) -> dict[str, Any]:
        """Load risk_boosting section from rules.yaml (cached in RulesEngine raw)."""
        try:
            import yaml
            from pathlib import Path
            raw = yaml.safe_load(
                Path("config/rules.yaml").read_text(encoding="utf-8")
            )
            return raw.get("risk_boosting", {})
        except Exception:
            return {}

    def _apply_boost(
        self,
        combined: float,
        src_ip: str,
        session,
        boost_cfg: dict,
        rr,
    ) -> tuple[float, bool]:
        """Query DB history and apply repeat-offender multiplier if warranted."""
        try:
            from app.db.models import Detection
            from sqlalchemy import desc

            cfg = boost_cfg.get("repeated_detection_boost", {})
            lookback = int(cfg.get("lookback_windows", 5))
            min_flags = int(cfg.get("min_prior_flags", 2))
            mult = float(cfg.get("multiplier", 1.25))

            recent = (
                session.query(Detection)
                .filter(Detection.src_ip == src_ip, Detection.decision != "allow")
                .order_by(desc(Detection.created_at))
                .limit(lookback)
                .all()
            )
            if len(recent) >= min_flags:
                new_combined = min(1.0, combined * mult)
                logger.debug(
                    "Risk boost applied for %s (%d prior flags): %.3f → %.3f",
                    src_ip, len(recent), combined, new_combined,
                )
                return new_combined, True
        except Exception as exc:
            logger.debug("Risk boost query failed: %s", exc)
        return combined, False
