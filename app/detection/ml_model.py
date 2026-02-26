from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np

from app.config import load_config
from app.features.feature_types import FeatureVector


@dataclass(frozen=True)
class MLResult:
    score: float  # 0..1, higher means more anomalous
    model_used: str


class MLModel:
    """
    MVP behavior:
    - If a trained IsolationForest exists on disk, use it.
    - Otherwise use a lightweight heuristic anomaly score so the pipeline is runnable from day 1.
    """

    def __init__(self):
        self.cfg = load_config().raw
        self.enabled = bool(self.cfg.get("ml", {}).get("enabled", True))
        self.model_path = Path(self.cfg.get("ml", {}).get("model_path", "./models/isolation_forest.pkl"))
        self._model = None
        self._loaded = False

    def _try_load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled:
            return
        if not self.model_path.exists():
            return
        try:
            import joblib  # type: ignore

            self._model = joblib.load(self.model_path)
        except Exception:
            self._model = None

    def score(self, fv: FeatureVector) -> MLResult:
        self._try_load()
        if not self.enabled:
            return MLResult(score=0.0, model_used="disabled")

        x = np.array([fv.to_numeric_vector()], dtype=float)

        if self._model is not None:
            # IsolationForest: score_samples -> higher is less abnormal.
            try:
                raw = float(self._model.score_samples(x)[0])
                # Map roughly to 0..1 (heuristic normalization).
                # Typical range often around [-0.8, 0.2]; clamp robustly.
                normalized = (0.2 - raw) / 1.0
                return MLResult(score=float(np.clip(normalized, 0.0, 1.0)), model_used="isolation_forest")
            except Exception:
                pass

        # Heuristic fallback: combine fanout + throughput + port diversity
        bytes_total = float(fv.total_bytes_sent + fv.total_bytes_received)
        fanout = float(fv.num_unique_dst_ips)
        port_div = float(fv.distinct_dst_ports)

        # log scaling keeps it stable across networks
        throughput_score = np.clip(np.log10(bytes_total + 1) / 8.0, 0.0, 1.0)
        fanout_score = np.clip(fanout / 80.0, 0.0, 1.0)
        port_score = np.clip(port_div / 25.0, 0.0, 1.0)

        score = float(np.clip(0.45 * throughput_score + 0.40 * fanout_score + 0.15 * port_score, 0.0, 1.0))
        return MLResult(score=score, model_used="heuristic_v0")

