"""Blocked IPs admin review — list, unblock, and annotate blocked devices."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.db.db_session import SessionLocal
from app.db.models import Alert, BlockedIP

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------

@router.get("/blocked", response_class=HTMLResponse)
def blocked_page(request: Request, db: Session = Depends(get_db)):
    """Admin review page — all blocked IPs with unblock controls."""
    blocked = (
        db.query(BlockedIP)
        .order_by(desc(BlockedIP.blocked_at))
        .all()
    )

    # Attach recent alerts for each IP so admin has context
    enriched = []
    for b in blocked:
        recent_alerts = (
            db.query(Alert)
            .filter(Alert.src_ip == b.ip_address)
            .order_by(desc(Alert.created_at))
            .limit(3)
            .all()
        )
        enriched.append({"block": b, "alerts": recent_alerts})

    active_count   = sum(1 for b in blocked if b.status == "blocked")
    unblocked_count = sum(1 for b in blocked if b.status == "unblocked")

    return templates.TemplateResponse(
        request,
        "blocked.html",
        {
            "items": enriched,
            "active_count": active_count,
            "unblocked_count": unblocked_count,
        },
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@router.post("/api/blocked/{ip}/unblock")
def api_unblock(
    ip: str,
    note: str = Form(default=""),
    db: Session = Depends(get_db),
):
    """
    Unblock an IP address.  Removes the OS firewall rule and marks the
    DB record as unblocked.  Admin adds an optional review note.
    """
    from app.blocking.firewall import unblock_ip
    success = unblock_ip(ip, note=note, unblocked_by="admin")
    return JSONResponse({
        "success": success,
        "ip": ip,
        "note": note,
        "message": f"Unblocked {ip}" if success else f"Failed to remove OS rule for {ip} — check privileges.",
    })


@router.get("/api/blocked", response_class=JSONResponse)
def api_blocked_list(db: Session = Depends(get_db)):
    """Return all blocked IP records as JSON."""
    rows = db.query(BlockedIP).order_by(desc(BlockedIP.blocked_at)).all()
    return JSONResponse([
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "reason": r.reason,
            "threat_type": r.threat_type,
            "risk_score": r.risk_score,
            "blocked_by": r.blocked_by,
            "status": r.status,
            "blocked_at": r.blocked_at.isoformat() if r.blocked_at else None,
            "unblocked_at": r.unblocked_at.isoformat() if r.unblocked_at else None,
            "unblocked_by": r.unblocked_by,
            "unblock_note": r.unblock_note,
        }
        for r in rows
    ])
