"""Background service that runs the capture → detect → alert pipeline in a thread."""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from app.capture.capture_runner import CaptureOutput, run_capture_loop
from app.capture.packet_source import auto_detect_interface
from app.config import load_config
from app.db.db_session import SessionLocal, init_db
from app.db.models import Device
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_extractor import FeatureExtractor
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.detection.dns_intelligence import DNSIntelligenceModule
from app.utils.time_utils import utcnow

logger = logging.getLogger("netscan.live")


@dataclass
class LiveStats:
    """Thread-safe live capture statistics."""
    running: bool = False
    interface: str | None = None
    started_at: float | None = None
    windows_processed: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    total_alerts_created: int = 0
    last_window_packets: int = 0
    last_window_bytes: int = 0
    last_window_time: float | None = None
    active_ips: set = field(default_factory=set)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        uptime = 0.0
        if self.started_at:
            uptime = time.time() - self.started_at
        return {
            "running": self.running,
            "interface": self.interface,
            "uptime_seconds": round(uptime, 1),
            "windows_processed": self.windows_processed,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_alerts_created": self.total_alerts_created,
            "last_window_packets": self.last_window_packets,
            "last_window_bytes": self.last_window_bytes,
            "active_ips": sorted(list(self.active_ips))[:50],
            "packets_per_second": round(self.total_packets / max(uptime, 1), 1),
            "bytes_per_second": round(self.total_bytes / max(uptime, 1), 1),
            "error": self.error,
        }


class LiveCaptureService:
    """Singleton service running the capture pipeline in a background thread."""

    _instance: LiveCaptureService | None = None

    def __init__(self):
        self.stats = LiveStats()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> LiveCaptureService:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def is_running(self) -> bool:
        return self.stats.running

    def start(self, interface: str | None = None) -> dict[str, Any]:
        """Start live capture in background thread."""
        with self._lock:
            if self.stats.running:
                return {"status": "already_running", **self.stats.to_dict()}

            iface = interface or auto_detect_interface()
            mode = "scapy"
            if not iface:
                logger.warning("No network interface found. Scapy will attempt to capture on default or fail.")
                mode = "scapy"

            self._stop_event.clear()
            self.stats = LiveStats(running=True, interface=iface, started_at=time.time())

            self._thread = threading.Thread(
                target=self._run_pipeline,
                args=(iface, "scapy"),
                daemon=True,
                name="netscan-capture",
            )
            self._thread.start()
            logger.info("Live capture started on %s", iface)
            return {"status": "started", **self.stats.to_dict()}

    def stop(self) -> dict[str, Any]:
        """Stop live capture."""
        with self._lock:
            if not self.stats.running:
                return {"status": "not_running"}
            self._stop_event.set()
            self.stats.running = False
            logger.info("Live capture stop requested")
            return {"status": "stopped", **self.stats.to_dict()}

    def _run_pipeline(self, interface: str, mode: str = "scapy") -> None:
        """Main pipeline loop running in background thread."""
        try:
            cfg = load_config().raw
            from app.capture.pipeline import ProcessingPipeline
            pipeline = ProcessingPipeline(int(cfg["app"]["window_seconds"]))

            # Catch-up phase: process any historical unprocessed features
            try:
                session = SessionLocal()
                processed = pipeline.run_batch_detection(session, limit=50)
                if processed > 0:
                    logger.info("Live service catch-up: processed %d historical windows.", processed)
                    session.commit()
            except Exception:
                logger.exception("Catch-up phase failed")
            finally:
                session.close()

            for capture_out in run_capture_loop(
                mode=mode,
                interface=interface,
            ):
                if self._stop_event.is_set():
                    break

                session = SessionLocal()
                try:
                    res = pipeline.process_window(session, capture_out)
                    session.commit()

                    # Update stats
                    self.stats.windows_processed += 1
                    self.stats.total_packets += res["packets"]
                    self.stats.total_bytes += res["bytes"]
                    self.stats.last_window_packets = res["packets"]
                    self.stats.last_window_bytes = res["bytes"]
                    self.stats.last_window_time = time.time()
                    self.stats.total_alerts_created += res["alerts_count"]
                    for ip in res["active_ips"]:
                        self.stats.active_ips.add(ip)

                except Exception:
                    session.rollback()
                    logger.exception("Error processing window #%d", self.stats.windows_processed)
                finally:
                    session.close()

        except Exception as e:
            logger.exception("Live capture pipeline failed")
            self.stats.error = str(e)
        finally:
            self.stats.running = False
            logger.info("Live capture pipeline stopped.")
