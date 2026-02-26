from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from app.features.feature_types import FeatureVector


@dataclass(frozen=True)
class RuleResult:
    score: float
    hits: dict[str, Any]
    guessed_threat_type: str | None


class RulesEngine:
    def __init__(self, rules_path: str | Path = "config/rules.yaml"):
        self.rules_path = Path(rules_path)
        self._rules = yaml.safe_load(self.rules_path.read_text(encoding="utf-8"))["rules"]

    def evaluate(self, fv: FeatureVector) -> RuleResult:
        hits: dict[str, Any] = {}
        total_score = 0.0
        guessed: str | None = None

        observed_ports = set((fv.extra.get("observed_dst_ports") or []))
        observed_domains = [d.lower() for d in (fv.extra.get("observed_domains") or [])]

        vpn_udp = self._rules.get("vpn_ports_udp", {})
        if vpn_udp.get("enabled"):
            vpn_ports = set(vpn_udp.get("ports") or [])
            if fv.udp_flow_count > 0 and len(observed_ports & vpn_ports) > 0:
                hits["vpn_ports_udp"] = {
                    "matched_ports": sorted(list(observed_ports & vpn_ports)),
                    "description": vpn_udp.get("description", ""),
                    "score": float(vpn_udp.get("score", 0.0)),
                }
                total_score += float(vpn_udp.get("score", 0.0))
                guessed = guessed or "vpn_usage"

        torrent_tcp = self._rules.get("torrent_ports_tcp", {})
        if torrent_tcp.get("enabled"):
            torrent_ports = set(torrent_tcp.get("ports") or [])
            if fv.tcp_flow_count > 0 and len(observed_ports & torrent_ports) > 0:
                hits["torrent_ports_tcp"] = {
                    "matched_ports": sorted(list(observed_ports & torrent_ports)),
                    "description": torrent_tcp.get("description", ""),
                    "score": float(torrent_tcp.get("score", 0.0)),
                }
                total_score += float(torrent_tcp.get("score", 0.0))
                guessed = guessed or "pirated_content"

        keywords_rule = self._rules.get("restricted_domain_keywords", {})
        if keywords_rule.get("enabled") and observed_domains:
            keyword_groups: dict[str, list[str]] = keywords_rule.get("keywords") or {}
            scores: dict[str, float] = keywords_rule.get("score") or {}
            for category, keywords in keyword_groups.items():
                matched = sorted({k for k in keywords if any(k in d for d in observed_domains)})
                if matched:
                    score = float(scores.get(category, 0.0))
                    hits[f"restricted_domain_keywords.{category}"] = {
                        "matched_keywords": matched,
                        "description": keywords_rule.get("description", ""),
                        "score": score,
                    }
                    total_score += score
                    if category == "gambling":
                        guessed = "gambling_access"
                    elif category == "piracy":
                        guessed = "pirated_content"

        fanout = self._rules.get("high_fanout_connections", {})
        if fanout.get("enabled"):
            thr = int(fanout.get("unique_dst_ip_threshold") or 0)
            if thr > 0 and fv.num_unique_dst_ips >= thr:
                score = float(fanout.get("score", 0.0))
                hits["high_fanout_connections"] = {
                    "unique_dst_ips": fv.num_unique_dst_ips,
                    "threshold": thr,
                    "description": fanout.get("description", ""),
                    "score": score,
                }
                total_score += score

        total_score = min(1.0, total_score)
        return RuleResult(score=total_score, hits=hits, guessed_threat_type=guessed)

