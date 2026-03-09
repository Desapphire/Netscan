#!/usr/bin/env python
"""Run detection on existing feature rows that haven't been processed yet.

Useful for batch / replay scenarios where features were written by a
separate capture process (or from a CSV import).
"""
from __future__ import annotations

import logging
import os
import sys

from sqlalchemy import func

from app.config import load_config
from app.db.db_session import SessionLocal, init_db
from app.db.models import Detection, NetworkFeature
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_types import FeatureVector
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.utils.logging_utils import setup_logging


def main() -> None:
    setup_logging()
    logger = logging.getLogger("netscan.batch_detect")
    init_db()

    detector = HybridDetector()
    ai_logic = AIDecisionLogic()
    alert_mgr = AlertManager()
    notifier = Notifier()

    session = SessionLocal()
    try:
        # Find feature rows with no detection yet
        already = session.query(Detection.feature_id).subquery()
        unprocessed = (
            session.query(NetworkFeature)
            .filter(~NetworkFeature.id.in_(session.query(already.c.feature_id)))
            .order_by(NetworkFeature.window_start)
            .all()
        )
        logger.info("Found %d unprocessed feature rows", len(unprocessed))

        for nf in unprocessed:
            fv = FeatureVector(
                window_start=nf.window_start,
                window_end=nf.window_end,
                src_ip=nf.src_ip,
                dst_category=nf.dst_category,
                num_flows=nf.num_flows,
                num_unique_dst_ips=nf.num_unique_dst_ips,
                num_unique_domains=nf.num_unique_domains,
                total_bytes_sent=nf.total_bytes_sent,
                total_bytes_received=nf.total_bytes_received,
                avg_packet_size=nf.avg_packet_size,
                std_packet_size=nf.std_packet_size,
                avg_inter_packet_time=nf.avg_inter_packet_time,
                std_inter_packet_time=nf.std_inter_packet_time,
                tcp_flow_count=nf.tcp_flow_count,
                udp_flow_count=nf.udp_flow_count,
                dns_query_count=nf.dns_query_count,
                distinct_dst_ports=nf.distinct_dst_ports,
                top_port=nf.top_port,
                ratio_known_vpn_ips=nf.ratio_known_vpn_ips,
                ratio_known_restricted_domains=nf.ratio_known_restricted_domains,
                extra=nf.extra or {},
            )

            dr = detector.detect(fv)
            det = alert_mgr.persist_detection(session, fv, dr, nf.id)

            ai_result = None
            ai_id = None
            if ai_logic.should_escalate(dr):
                ai_result = ai_logic.assess_sync(fv, dr)
                ai_obj = alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            if dr.decision != "allow":
                alert = alert_mgr.create_alert(
                    session, fv, dr, det.id,
                    ai=ai_result, ai_assessment_id=ai_id,
                )
                notifier.notify(alert.title, alert.summary, alert.severity)

            logger.info(
                "  %s → risk=%.2f (%s)",
                fv.src_ip, dr.combined_risk, dr.decision,
            )

        session.commit()
        logger.info("Batch detection complete.")
    except Exception:
        session.rollback()
        logger.exception("Batch detection failed")
    finally:
        session.close()


if __name__ == "__main__":
    main()
