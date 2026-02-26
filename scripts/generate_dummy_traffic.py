#!/usr/bin/env python
"""
Generate synthetic traffic data and feed it through the pipeline.

Produces three simulated scenarios:
  1. VPN usage (OpenVPN/WireGuard pattern)
  2. Gambling site browsing
  3. Torrent / pirated content downloading

Writes features + detections + alerts into the DB so the dashboard has
data to display during a demo.
"""
from __future__ import annotations

import logging
import os
import random
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from datetime import datetime, timezone

from app.config import load_config
from app.db.db_session import SessionLocal, init_db
from app.db.models import Device
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_types import FeatureVector
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.utils.logging_utils import setup_logging
from app.utils.time_utils import utcnow


def _ts() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


SCENARIOS: list[dict] = [
    {
        "label": "VPN usage (OpenVPN)",
        "src_ip": "10.0.5.23",
        "fv": dict(
            num_flows=45,
            num_unique_dst_ips=3,
            num_unique_domains=1,
            total_bytes_sent=8_000_000,
            total_bytes_received=25_000_000,
            avg_packet_size=1300.0,
            std_packet_size=50.0,
            avg_inter_packet_time=0.01,
            std_inter_packet_time=0.002,
            tcp_flow_count=0,
            udp_flow_count=45,
            dns_query_count=1,
            distinct_dst_ports=1,
            top_port=1194,
            ratio_known_vpn_ips=0.9,
            ratio_known_restricted_domains=0.0,
            extra={
                "observed_dst_ports": [1194],
                "observed_domains": ["vpn-node.example.com"],
            },
        ),
    },
    {
        "label": "Gambling site browsing",
        "src_ip": "10.0.5.42",
        "fv": dict(
            num_flows=80,
            num_unique_dst_ips=15,
            num_unique_domains=6,
            total_bytes_sent=1_000_000,
            total_bytes_received=7_000_000,
            avg_packet_size=700.0,
            std_packet_size=300.0,
            avg_inter_packet_time=0.05,
            std_inter_packet_time=0.03,
            tcp_flow_count=80,
            udp_flow_count=0,
            dns_query_count=20,
            distinct_dst_ports=2,
            top_port=443,
            ratio_known_vpn_ips=0.0,
            ratio_known_restricted_domains=0.7,
            extra={
                "observed_dst_ports": [80, 443],
                "observed_domains": [
                    "best-casino-bet.example",
                    "live-poker.example",
                    "sportsbook-odds.example",
                    "casino-royale.example",
                    "bet365-mirror.example",
                    "poker-stars.example",
                ],
            },
        ),
    },
    {
        "label": "Torrent / pirated content",
        "src_ip": "10.0.5.99",
        "fv": dict(
            num_flows=200,
            num_unique_dst_ips=60,
            num_unique_domains=2,
            total_bytes_sent=15_000_000,
            total_bytes_received=40_000_000,
            avg_packet_size=1000.0,
            std_packet_size=300.0,
            avg_inter_packet_time=0.005,
            std_inter_packet_time=0.003,
            tcp_flow_count=120,
            udp_flow_count=80,
            dns_query_count=5,
            distinct_dst_ports=20,
            top_port=6881,
            ratio_known_vpn_ips=0.1,
            ratio_known_restricted_domains=0.3,
            extra={
                "observed_dst_ports": [6881, 6882, 6889, 51413, 443],
                "observed_domains": ["torrent-tracker.example", "pirate-index.example"],
            },
        ),
    },
    {
        "label": "Normal browsing",
        "src_ip": "10.0.5.10",
        "fv": dict(
            num_flows=12,
            num_unique_dst_ips=5,
            num_unique_domains=4,
            total_bytes_sent=200_000,
            total_bytes_received=1_500_000,
            avg_packet_size=600.0,
            std_packet_size=250.0,
            avg_inter_packet_time=0.2,
            std_inter_packet_time=0.15,
            tcp_flow_count=12,
            udp_flow_count=0,
            dns_query_count=4,
            distinct_dst_ports=2,
            top_port=443,
            ratio_known_vpn_ips=0.0,
            ratio_known_restricted_domains=0.0,
            extra={
                "observed_dst_ports": [80, 443],
                "observed_domains": [
                    "google.com",
                    "stackoverflow.com",
                    "github.com",
                    "wikipedia.org",
                ],
            },
        ),
    },
]


def main() -> None:
    setup_logging()
    logger = logging.getLogger("netscan.dummy_traffic")
    init_db()

    detector = HybridDetector()
    ai_logic = AIDecisionLogic()
    alert_mgr = AlertManager()
    notifier = Notifier()

    now = _ts()

    session = SessionLocal()
    try:
        for sc in SCENARIOS:
            ws = now
            we = now  # window_end is effectively "now"

            fv = FeatureVector(
                window_start=ws,
                window_end=we,
                src_ip=sc["src_ip"],
                **sc["fv"],
            )

            nf = alert_mgr.persist_feature(session, fv)
            dr = detector.detect(fv)
            det = alert_mgr.persist_detection(session, fv, dr, nf.id)

            logger.info(
                "[%s] %s → risk=%.2f (%s) rule=%.2f ml=%.2f",
                sc["label"], sc["src_ip"],
                dr.combined_risk, dr.decision, dr.rule_score, dr.ml_score,
            )

            ai_result = None
            ai_id = None
            if ai_logic.should_escalate(dr):
                ai_result = ai_logic.assess_sync(fv, dr)
                ai_obj = alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id
                logger.info("  AI: %s (%s) — %s", ai_result.threat_type, ai_result.severity, ai_result.explanation[:80])

            if dr.decision != "allow":
                alert = alert_mgr.create_alert(session, fv, dr, det.id, ai=ai_result, ai_assessment_id=ai_id)
                notifier.notify(alert.title, alert.summary, alert.severity)

            # Upsert device
            dev = session.query(Device).filter(Device.ip_address == sc["src_ip"]).first()
            if dev:
                dev.last_seen = utcnow()
            else:
                session.add(Device(ip_address=sc["src_ip"], last_seen=utcnow()))

        session.commit()
        logger.info("✓ Dummy traffic generation complete — %d scenarios processed.", len(SCENARIOS))
    except Exception:
        session.rollback()
        logger.exception("Dummy traffic generation failed")
    finally:
        session.close()


if __name__ == "__main__":
    main()
