from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AppConfig:
    raw: dict[str, Any]

    @property
    def window_seconds(self) -> int:
        return int(self.raw["app"]["window_seconds"])

    @property
    def slide_seconds(self) -> int:
        return int(self.raw["app"]["slide_seconds"])

    @property
    def db_url(self) -> str:
        import os
        if os.environ.get("NETSCAN_TEST"):
            return "sqlite:///:memory:"
        return str(self.raw["db"]["url"])


def load_config(config_path: str | Path | None = None) -> AppConfig:
    path = Path(config_path) if config_path else Path("config/app_config.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return AppConfig(raw=data)

