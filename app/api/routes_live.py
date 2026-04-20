"""Live monitoring API endpoints — start/stop capture and get real-time stats."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.capture.live_capture_service import LiveCaptureService

router = APIRouter()


class StartRequest(BaseModel):
    interface: str | None = None


@router.get("/status")
def live_status():
    """Current capture pipeline status."""
    svc = LiveCaptureService.get_instance()
    return svc.stats.to_dict()


@router.get("/stats")
def live_stats():
    """Real-time stats for dashboard widgets."""
    svc = LiveCaptureService.get_instance()
    return svc.stats.to_dict()


@router.post("/start")
def live_start(body: StartRequest | None = None):
    """Start the capture pipeline on the given (or auto-detected) interface."""
    svc = LiveCaptureService.get_instance()
    iface = body.interface if body else None
    return svc.start(interface=iface)


@router.post("/stop")
def live_stop():
    """Stop the capture pipeline."""
    svc = LiveCaptureService.get_instance()
    return svc.stop()
