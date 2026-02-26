#!/usr/bin/env python
"""Run the FastAPI admin dashboard and API server."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import uvicorn
from app.api.main import create_app

app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "scripts.run_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
