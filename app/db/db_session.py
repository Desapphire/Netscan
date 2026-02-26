from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import load_config
from app.db.models import Base


def _get_engine():
    cfg = load_config()
    # check_same_thread is required for SQLite with FastAPI dev usage
    connect_args = {"check_same_thread": False} if cfg.db_url.startswith("sqlite") else {}
    return create_engine(cfg.db_url, future=True, connect_args=connect_args)


engine = _get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

