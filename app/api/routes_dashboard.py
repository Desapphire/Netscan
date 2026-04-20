"""Dashboard HTML routes (server-side rendered with Jinja2)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.db.db_session import SessionLocal
from app.db.models import AIAssessment, Alert, Detection, DNSAnalysis, Device

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar() or 0
    critical = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
    high = db.query(func.count(Alert.id)).filter(Alert.severity == "high").scalar() or 0
    
    total_detections = db.query(func.count(Detection.id)).scalar() or 0
    total_dns = db.query(func.count(DNSAnalysis.id)).scalar() or 0

    recent = (
        db.query(Alert)
        .order_by(desc(Alert.created_at))
        .limit(25)
        .all()
    )

    recent_dns = (
        db.query(DNSAnalysis)
        .filter(DNSAnalysis.category != 'normal')
        .order_by(desc(DNSAnalysis.created_at))
        .limit(10)
        .all()
    )

    recent_detections = (
        db.query(Detection)
        .filter(Detection.decision != 'allow')
        .order_by(desc(Detection.created_at))
        .limit(10)
        .all()
    )

    by_type = dict(
        db.query(Alert.threat_type, func.count(Alert.id))
        .group_by(Alert.threat_type)
        .all()
    )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical": critical,
            "high": high,
            "total_detections": total_detections,
            "total_dns": total_dns,
            "recent_alerts": recent,
            "recent_dns": recent_dns,
            "recent_detections": recent_detections,
            "by_type": by_type,
        },
    )


@router.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail_page(alert_id: int, request: Request, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    detection = None
    ai = None
    if alert and alert.detection_id:
        detection = db.query(Detection).filter(Detection.id == alert.detection_id).first()
    if alert and alert.ai_assessment_id:
        ai = db.query(AIAssessment).filter(AIAssessment.id == alert.ai_assessment_id).first()

    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "alert": alert,
            "detection": detection,
            "ai": ai,
        },
    )

@router.get("/devices", response_class=HTMLResponse)
def devices_page(request: Request, db: Session = Depends(get_db)):
    devices = db.query(Device).order_by(desc(Device.last_seen)).all()
    
    device_data = []
    for d in devices:
        alerts = db.query(Alert).filter(Alert.src_ip == d.ip_address, Alert.status == "open").all()
        highest_sev = None
        if alerts:
            highest_sev = max([a.severity for a in alerts], key=lambda x: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(x, 0))
            
        device_data.append({
            "device": d,
            "open_alerts": len(alerts),
            "highest_severity": highest_sev,
            "alerts": alerts
        })
    
    # Filter out clean devices - only show flagged ones
    device_data = [d for d in device_data if d["open_alerts"] > 0]
    
    def sort_key(item):
        alert_score = 0
        if item["open_alerts"] > 0:
            alert_score = 10 + {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(item["highest_severity"], 0)
        
        last_seen = item["device"].last_seen
        # If last_seen is None for some reason, use a fallback
        import datetime
        fallback = datetime.datetime.min
        return (alert_score, last_seen or fallback)

    device_data.sort(key=sort_key, reverse=True)

    return templates.TemplateResponse(
        request,
        "devices.html",
        {
            "devices": device_data,
        },
    )
