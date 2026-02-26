"""Feature extraction – converts raw flows into per-device feature vectors."""
from __future__ import annotations

import logging
from typing import Iterable

from app.capture.flow_aggregator import FlowAggregator
from app.capture.types import PacketMeta
from app.features.feature_types import FeatureVector
from app.utils.ip_utils import compute_vpn_ratio

logger = logging.getLogger("netscan.features")


class FeatureExtractor:
    """Wraps FlowAggregator and enriches the resulting feature vectors."""

    def __init__(self, window_seconds: int = 20):
        self.aggregator = FlowAggregator(window_seconds)

    def extract(
        self,
        packets: Iterable[PacketMeta],
        window_start_ts: float,
        window_end_ts: float,
        *,
        restricted_keywords: dict[str, list[str]] | None = None,
    ) -> list[FeatureVector]:
        """
        Run flow aggregation then enrich with VPN-IP ratio and
        restricted-domain ratio.
        """
        fvs = self.aggregator.aggregate_window(packets, window_start_ts, window_end_ts)

        if restricted_keywords is None:
            restricted_keywords = {
                "gambling": ["casino", "bet", "poker", "sportsbook"],
                "piracy": ["torrent", "pirate", "crack", "warez"],
            }
        all_keywords = [kw for group in restricted_keywords.values() for kw in group]

        enriched: list[FeatureVector] = []
        for fv in fvs:
            dst_ips = fv.extra.get("observed_dst_ips") or []
            domains = [d.lower() for d in (fv.extra.get("observed_domains") or [])]

            vpn_ratio = compute_vpn_ratio(dst_ips) if dst_ips else fv.ratio_known_vpn_ips

            restricted_hits = sum(
                1 for d in domains if any(kw in d for kw in all_keywords)
            )
            restricted_ratio = restricted_hits / max(len(domains), 1)

            # Determine dst_category heuristic
            dst_cat = _guess_category(fv, vpn_ratio, restricted_ratio, domains, restricted_keywords)

            enriched.append(
                fv.model_copy(
                    update={
                        "ratio_known_vpn_ips": vpn_ratio,
                        "ratio_known_restricted_domains": restricted_ratio,
                        "dst_category": dst_cat,
                    }
                )
            )

        logger.debug("Extracted %d feature vectors for window", len(enriched))
        return enriched


def _guess_category(
    fv: FeatureVector,
    vpn_ratio: float,
    restricted_ratio: float,
    domains: list[str],
    kw_groups: dict[str, list[str]],
) -> str | None:
    """Best-effort category from metadata."""
    if vpn_ratio >= 0.5:
        return "vpn"
    for cat, keywords in kw_groups.items():
        if any(kw in d for d in domains for kw in keywords):
            return cat
    if restricted_ratio >= 0.3:
        return "restricted"
    return None
