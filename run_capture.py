#!/usr/bin/env python
"""Run the full capture → feature → detection → alert pipeline."""
from __future__ import annotations

import argparse
import logging

from app.config import load_config
from app.capture.capture_runner import run_capture_loop
from app.capture.flow_aggregator import FlowAggregator
from app.features.feature_extractor import FeatureExtractor
from app.detection.hybrid_detector import HybridDetector
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.db.db_session import SessionLocal, init_db
from app.db.models import Device
from app.utils.logging_utils import setup_logging
from app.utils.time_utils import utcnow


def main() -> None:
    parser = argparse.ArgumentParser(description="NetScan Capture & Detection Pipeline")
    parser.add_argument("--mode", default="scapy", choices=["scapy"],
                        help="Capture mode")
    parser.add_argument("--interface", default=None, help="NIC for scapy mode")
    parser.add_argument("--bpf", default=None, help="BPF filter")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("netscan.pipeline")
    logger.info("Starting NetScan pipeline in '%s' mode", args.mode)

    init_db()
    cfg = load_config().raw

    extractor = FeatureExtractor(int(cfg["app"]["window_seconds"]))
    detector = HybridDetector()
    ai_logic = AIDecisionLogic()
    alert_mgr = AlertManager()
    notifier = Notifier()

    window_count = 0

    for capture_out in run_capture_loop(
        mode=args.mode,
        interface=args.interface,
        bpf_filter=args.bpf,
    ):
        window_count += 1
        logger.info(
            "Window #%d: %d packets (%.1fs)",
            window_count,
            len(capture_out.packets),
            capture_out.window_end_ts - capture_out.window_start_ts,
        )

        fvs = extractor.extract(
            capture_out.packets,
            capture_out.window_start_ts,
            capture_out.window_end_ts,
        )

        session = SessionLocal()
        try:
            for fv in fvs:
                # Persist feature
                nf = alert_mgr.persist_feature(session, fv)

                # Detect
                dr = detector.detect(fv)
                det = alert_mgr.persist_detection(session, fv, dr, nf.id)

                logger.info(
                    "  %s → risk=%.2f (%s) rule=%.2f ml=%.2f %s",
                    fv.src_ip,
                    dr.combined_risk,
                    dr.decision,
                    dr.rule_score,
                    dr.ml_score,
                    f"[{dr.guessed_threat_type}]" if dr.guessed_threat_type else "",
                )

                ai_result = None
                ai_id = None

                # AI review if needed
                if ai_logic.should_escalate(dr):
                    ai_result = ai_logic.assess_sync(fv, dr)
                    ai_obj = alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                    ai_id = ai_obj.id
                    logger.info(
                        "  AI → %s (%s): %s",
                        ai_result.threat_type,
                        ai_result.severity,
                        ai_result.explanation[:100],
                    )

                # Create alert for non-allow decisions
                if dr.decision != "allow":
                    alert = alert_mgr.create_alert(
                        session, fv, dr, det.id,
                        ai=ai_result,
                        ai_assessment_id=ai_id,
                    )
                    notifier.notify(
                        title=alert.title,
                        summary=alert.summary,
                        severity=alert.severity,
                    )

                # Upsert device
                device = session.query(Device).filter(Device.ip_address == fv.src_ip).first()
                if device:
                    device.last_seen = utcnow()
                else:
                    session.add(Device(ip_address=fv.src_ip, last_seen=utcnow()))

            session.commit()
        except Exception:
            session.rollback()
            logger.exception("Error processing window #%d", window_count)
        finally:
            session.close()


if __name__ == "__main__":
    main()
