#!/usr/bin/env python
"""
NetScan Live Monitor — One-click launcher.

Starts the API dashboard and automatically begins live network capture.
Run as Administrator for packet capture permissions.

Usage:
    python run_live.py                     # auto-detect interface
    python run_live.py --interface "Wi-Fi"  # specify interface
    python run_live.py --no-capture         # start dashboard only
"""
from __future__ import annotations

import argparse
import ctypes
import logging
import os
import sys
import threading
import time
import webbrowser

from app.utils.logging_utils import setup_logging


def is_admin() -> bool:
    """Check if running with admin privileges (Windows)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="NetScan Live Monitor")
    parser.add_argument("--interface", default=None,
                        help="Network interface name (e.g., 'Wi-Fi', 'Ethernet')")
    parser.add_argument("--port", type=int, default=8000,
                        help="Dashboard port (default: 8000)")
    parser.add_argument("--no-capture", action="store_true",
                        help="Start dashboard only, don't auto-start capture")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't auto-open browser")
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger("netscan.launcher")

    # Warn if not admin
    if not is_admin():
        logger.warning(
            "⚠  Not running as Administrator! Live capture may fail. "
            "Right-click your terminal → 'Run as Administrator'."
        )

    # Import app components
    from app.db.db_session import init_db
    init_db()

    from app.capture.live_capture_service import LiveCaptureService
    svc = LiveCaptureService.get_instance()

    # Auto-start capture unless disabled
    if not args.no_capture:
        logger.info("Starting live capture...")
        result = svc.start(interface=args.interface)
        if result.get("status") == "started":
            logger.info("✓ Live capture started on %s", result.get("interface"))
        else:
            logger.warning("⚠  Capture start result: %s", result)

    # Open browser after a short delay
    if not args.no_browser:
        def _open_browser():
            time.sleep(2)
            url = f"http://localhost:{args.port}"
            logger.info("Opening browser at %s", url)
            webbrowser.open(url)
        threading.Thread(target=_open_browser, daemon=True).start()

    # Start uvicorn
    import uvicorn
    from run_api import app  # noqa: E402

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


if __name__ == "__main__":
    main()
