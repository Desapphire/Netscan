#!/usr/bin/env python
"""
NetScan Unified CLI Tool

Usage:
    python cli.py api          # Start dashboard & API server
    python cli.py capture      # Run packet capture & processing pipeline
    python cli.py live         # Run live capture & auto-open dashboard
    python cli.py detect       # Run detection on unprocessed features
"""
from __future__ import annotations

import argparse
import ctypes
import logging
import sys
import threading
import time
import webbrowser

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


def is_admin() -> bool:
    """Check if running with admin privileges (Windows)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
    except Exception:
        return False


def run_api(args: argparse.Namespace) -> None:
    """Run the FastAPI admin dashboard and API server."""
    import uvicorn
    # Delay import so it doesn't run during help output
    from app.api.main import create_app
    app = create_app()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def run_capture(args: argparse.Namespace) -> None:
    """Run the continuous capture and processing loop."""
    from app.capture.capture_runner import run_capture_loop
    setup_logging()
    conf = load_config()

    logging.getLogger("netscan.capture_main").info(
        "Starting capture runner in %s mode (interface: %s)",
        args.mode, args.interface or "auto"
    )

    try:
        run_capture_loop(
            mode=args.mode,
            interface=args.interface,
            window_sec=conf.app.window_seconds,
            slide_sec=conf.app.slide_seconds,
        )
    except KeyboardInterrupt:
        logging.getLogger("netscan.capture_main").info("Stopped gracefully by user.")


def run_live(args: argparse.Namespace) -> None:
    """Start the API dashboard and automatically begin live network capture."""
    setup_logging()
    logger = logging.getLogger("netscan.launcher")

    if not is_admin():
        logger.warning(
            "⚠  Not running as Administrator! Live capture may fail. "
            "Right-click your terminal → 'Run as Administrator'."
        )

    init_db()

    from app.capture.live_capture_service import LiveCaptureService
    svc = LiveCaptureService.get_instance()

    if not args.no_capture:
        logger.info("Starting live capture...")
        result = svc.start(interface=args.interface)
        if result.get("status") == "started":
            logger.info("✓ Live capture started on %s", result.get("interface"))
        else:
            logger.warning("⚠  Capture start result: %s", result)

    if not args.no_browser:
        def _open_browser():
            time.sleep(2)
            url = f"http://localhost:{args.port}"
            logger.info("Opening browser at %s", url)
            webbrowser.open(url)
        threading.Thread(target=_open_browser, daemon=True).start()

    import uvicorn
    from app.api.main import create_app
    app = create_app()

    logger.info("Starting NetScan dashboard on port %d...", args.port)
    logger.info("Press Ctrl+C to stop.")

    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=args.port,
            log_level="info",
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        svc.stop()


def run_detect(args: argparse.Namespace) -> None:
    """Run detection on existing feature rows that haven't been processed yet."""
    setup_logging()
    logger = logging.getLogger("netscan.batch_detect")
    init_db()

    detector = HybridDetector()
    ai_logic = AIDecisionLogic()
    alert_mgr = AlertManager()
    notifier = Notifier()

    session = SessionLocal()
    try:
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


def main() -> None:
    parser = argparse.ArgumentParser(description="NetScan Unified CLI Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # API Server command
    api_parser = subparsers.add_parser("api", help="Start the API server and dashboard")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host ID to bind the API Server")
    api_parser.add_argument("--port", type=int, default=8000, help="Port to bind the API Server")
    api_parser.add_argument("--reload", action="store_true", help="Enable hot-reload for the server")

    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Run the continuous packet capture pipeline")
    capture_parser.add_argument("--mode", choices=["scapy"], default="scapy", help="Capture backend mode")
    capture_parser.add_argument("--interface", help="Interface name or index. Required for scapy mode.")

    # Live monitor command
    live_parser = subparsers.add_parser("live", help="Start dashboard and live auto-capture")
    live_parser.add_argument("--interface", default=None, help="Network interface name (e.g., 'Wi-Fi')")
    live_parser.add_argument("--port", type=int, default=8000, help="Dashboard port (default: 8000)")
    live_parser.add_argument("--no-capture", action="store_true", help="Start dashboard only")
    live_parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")

    # Detection batch command
    detect_parser = subparsers.add_parser("detect", help="Run detection on unprocessed feature rows in DB")

    args = parser.parse_args()

    if args.command == "api":
        run_api(args)
    elif args.command == "capture":
        run_capture(args)
    elif args.command == "live":
        run_live(args)
    elif args.command == "detect":
        run_detect(args)


if __name__ == "__main__":
    main()
