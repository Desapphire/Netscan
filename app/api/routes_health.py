"""Health / status endpoint."""
from __future__ import annotations

from fastapi import APIRouter

from app.config import load_config

router = APIRouter()


@router.get("/health")
def health_check():
    cfg = load_config()
    return {
        "status": "ok",
        "app": cfg.raw.get("app", {}).get("name", "netscan"),
        "db": cfg.db_url.split("///")[-1] if "///" in cfg.db_url else cfg.db_url,
        "gemini_enabled": cfg.raw.get("gemini", {}).get("enabled", False),
    }
