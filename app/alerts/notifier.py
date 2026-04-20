"""Notification channels: console, email, Telegram."""
from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText
from typing import Any

from app.config import load_config

logger = logging.getLogger("netscan.notifier")


class Notifier:
    """Dispatches alert notifications through configured channels."""

    def __init__(self) -> None:
        cfg = load_config().raw.get("alerting", {})
        self.console_enabled: bool = cfg.get("console", True)
        self.db_enabled: bool = cfg.get("store_in_db", True)

        email_cfg = cfg.get("email", {})
        self.email_enabled: bool = email_cfg.get("enabled", False)
        self.smtp_host: str = email_cfg.get("smtp_host", "")
        self.smtp_port: int = int(email_cfg.get("smtp_port", 587))
        self.email_sender: str = email_cfg.get("sender", "")
        self.email_password: str = os.environ.get(email_cfg.get("password_env", ""), "")
        self.email_recipients: list[str] = email_cfg.get("recipients", [])

        tg_cfg = cfg.get("telegram", {})
        self.telegram_enabled: bool = tg_cfg.get("enabled", False)
        self.telegram_token: str = os.environ.get(tg_cfg.get("bot_token_env", ""), "")
        self.telegram_chat_id: str = str(tg_cfg.get("chat_id", ""))

    def notify(
        self,
        title: str,
        summary: str,
        severity: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Push a notification through all enabled channels."""
        if self.console_enabled:
            self._console(title, summary, severity)
        if self.email_enabled:
            self._email(title, summary, severity)
        if self.telegram_enabled:
            self._telegram(title, summary, severity)

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def _console(self, title: str, summary: str, severity: str) -> None:
        sev_colors = {
            "critical": "\033[91m",  # red
            "high": "\033[93m",      # yellow
            "medium": "\033[94m",    # blue
            "low": "\033[92m",       # green
        }
        reset = "\033[0m"
        color = sev_colors.get(severity, "")
        logger.warning(
            "%s[ALERT %s] %s%s — %s",
            color,
            severity.upper(),
            title,
            reset,
            summary[:200],
        )

    def _email(self, title: str, summary: str, severity: str) -> None:
        if not self.email_recipients:
            return
        try:
            body = f"Severity: {severity}\n\n{summary}"
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = f"[NetScan] {title}"
            msg["From"] = self.email_sender
            msg["To"] = ", ".join(self.email_recipients)
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_sender, self.email_password)
                server.sendmail(self.email_sender, self.email_recipients, msg.as_string())
            logger.info("Email alert sent: %s", title)
        except Exception as exc:
            logger.error("Failed to send email alert: %s", exc)

    def _telegram(self, title: str, summary: str, severity: str) -> None:
        try:
            import requests

            text = f"🚨 *{severity.upper()}*: {title}\n\n{summary[:500]}"
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            requests.post(
                url,
                json={
                    "chat_id": self.telegram_chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            logger.info("Telegram alert sent: %s", title)
        except Exception as exc:
            logger.error("Failed to send Telegram alert: %s", exc)
