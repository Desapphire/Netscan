import sys
import os
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger("netscan.firewall")


# ---------------------------------------------------------------------------
# OS-level firewall helpers
# ---------------------------------------------------------------------------

def _win_add_rules(ip_address: str, rule_name: str, safe_reason: str) -> bool:
    """Add Windows Firewall inbound + outbound block rules via PowerShell."""
    try:
        for direction in ("Inbound", "Outbound"):
            suffix = "IN" if direction == "Inbound" else "OUT"
            cmd = (
                f'powershell.exe -Command "New-NetFirewallRule '
                f"-DisplayName '{rule_name}_{suffix}' -Direction {direction} "
                f"-Action Block -RemoteAddress {ip_address} "
                f"-Description '{safe_reason}'\" "
            )
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode != 0 and "already exists" not in res.stderr.lower():
                logger.debug("PowerShell rule error (%s): %s", direction, res.stderr.strip())
                return False
        return True
    except Exception as exc:
        logger.error("Windows firewall error for %s: %s", ip_address, exc)
        return False


def _win_remove_rules(ip_address: str, rule_name: str) -> bool:
    """Remove Windows Firewall block rules for an IP."""
    try:
        for suffix in ("IN", "OUT"):
            cmd = (
                f'powershell.exe -Command "Remove-NetFirewallRule '
                f"-DisplayName '{rule_name}_{suffix}'\" "
            )
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return True
    except Exception as exc:
        logger.error("Windows firewall remove error for %s: %s", ip_address, exc)
        return False


def _linux_add_rules(ip_address: str, safe_reason: str) -> bool:
    """Add iptables INPUT + OUTPUT DROP rules for an IP."""
    try:
        if subprocess.run("iptables --version", shell=True, capture_output=True).returncode != 0:
            logger.error("iptables not found on this Linux system.")
            return False
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            check = f"sudo iptables -C {direction} {flag} {ip_address} -j DROP"
            if subprocess.run(check, shell=True, capture_output=True).returncode != 0:
                add = (
                    f"sudo iptables -A {direction} {flag} {ip_address} -j DROP "
                    f"-m comment --comment '{safe_reason}'"
                )
                subprocess.run(add, shell=True)
        return True
    except Exception as exc:
        logger.error("Linux firewall error for %s: %s", ip_address, exc)
        return False


def _linux_remove_rules(ip_address: str) -> bool:
    """Remove iptables DROP rules for an IP."""
    try:
        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            cmd = f"sudo iptables -D {direction} {flag} {ip_address} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True)
        return True
    except Exception as exc:
        logger.error("Linux firewall remove error for %s: %s", ip_address, exc)
        return False


# ---------------------------------------------------------------------------
# Privilege check — evaluated ONCE at import time so we warn exactly once.
# ---------------------------------------------------------------------------

def _has_privileges() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
        return os.getuid() == 0
    except Exception:
        return False


_PRIVILEGES_OK: bool = _has_privileges()

if not _PRIVILEGES_OK:
    logger.warning(
        "⚠  NetScan is NOT running as Administrator / root. "
        "Automatic IP blocking is DISABLED — detection and alerting still work normally. "
        "To enable blocking: right-click your terminal → 'Run as Administrator' "
        "then restart with:  python cli.py capture"
    )

def is_blocking_enabled() -> bool:
    """Return True if the system has privileges to apply firewall rules."""
    return _PRIVILEGES_OK


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def block_ip(
    ip_address: str,
    reason: str = "High Risk Detection",
    threat_type: str | None = None,
    risk_score: float = 0.0,
) -> bool:
    """
    Block *ip_address* at the OS firewall layer and record it in the DB.

    Returns True if the OS rule was applied (or already existed).
    Returns False silently if running without admin privileges.
    """
    if not _PRIVILEGES_OK:
        return False

    rule_name   = f"NetScan_Block_{ip_address}"
    safe_reason = reason.replace("'", "").replace('"', "")

    if sys.platform == "win32":
        success = _win_add_rules(ip_address, rule_name, safe_reason)
    else:
        success = _linux_add_rules(ip_address, safe_reason)

    if success:
        logger.warning(
            "🚫 FIREWALL BLOCK APPLIED — %s blocked. Reason: %s", ip_address, safe_reason
        )
        _persist_block(ip_address, reason, threat_type, risk_score)
    else:
        logger.error(
            "Firewall block FAILED for %s — ensure you are running as Administrator.",
            ip_address,
        )
    return success


def unblock_ip(ip_address: str, *, note: str = "", unblocked_by: str = "admin") -> bool:
    """
    Remove the OS firewall block for *ip_address* and mark its DB record as unblocked.

    Returns True if the OS rule was successfully removed.
    """
    rule_name = f"NetScan_Block_{ip_address}"

    if sys.platform == "win32":
        success = _win_remove_rules(ip_address, rule_name)
    else:
        success = _linux_remove_rules(ip_address)

    _mark_unblocked(ip_address, note=note, unblocked_by=unblocked_by)

    if success:
        logger.warning(
            "✅ FIREWALL UNBLOCK — %s unblocked by %s. Note: %s",
            ip_address, unblocked_by, note or "—",
        )
    else:
        logger.error("Failed to remove firewall rule for %s.", ip_address)
    return success


# ---------------------------------------------------------------------------
# DB persistence (internal helpers)
# ---------------------------------------------------------------------------

def _persist_block(
    ip_address: str,
    reason: str,
    threat_type: str | None,
    risk_score: float,
) -> None:
    """Record the block in the blocked_ips table."""
    try:
        from app.db.db_session import SessionLocal
        from app.db.models import BlockedIP
        session = SessionLocal()
        try:
            # Check for an existing active block row to avoid duplicates
            existing = (
                session.query(BlockedIP)
                .filter(BlockedIP.ip_address == ip_address, BlockedIP.status == "blocked")
                .first()
            )
            if not existing:
                session.add(BlockedIP(
                    ip_address=ip_address,
                    reason=reason,
                    threat_type=threat_type,
                    risk_score=risk_score,
                    blocked_by="auto",
                    status="blocked",
                    blocked_at=datetime.utcnow(),
                ))
                session.commit()
        except Exception as exc:
            session.rollback()
            logger.error("Failed to persist block record for %s: %s", ip_address, exc)
        finally:
            session.close()
    except Exception as exc:
        logger.error("DB import failed in _persist_block: %s", exc)


def _mark_unblocked(ip_address: str, *, note: str, unblocked_by: str) -> None:
    """Update the most recent active block record to unblocked."""
    try:
        from app.db.db_session import SessionLocal
        from app.db.models import BlockedIP
        session = SessionLocal()
        try:
            record = (
                session.query(BlockedIP)
                .filter(BlockedIP.ip_address == ip_address, BlockedIP.status == "blocked")
                .order_by(BlockedIP.blocked_at.desc())
                .first()
            )
            if record:
                record.status       = "unblocked"
                record.unblocked_at = datetime.utcnow()
                record.unblocked_by = unblocked_by
                record.unblock_note = note
                session.commit()
        except Exception as exc:
            session.rollback()
            logger.error("Failed to update block record for %s: %s", ip_address, exc)
        finally:
            session.close()
    except Exception as exc:
        logger.error("DB import failed in _mark_unblocked: %s", exc)



def block_ip_windows(ip_address: str, rule_name: str, safe_reason: str) -> bool:
    """Windows implementation using PowerShell New-NetFirewallRule."""
    try:
        cmd_in = (
            f'powershell.exe -Command "New-NetFirewallRule '
            f"-DisplayName '{rule_name}_IN' -Direction Inbound -Action Block "
            f"-RemoteAddress {ip_address} -Description '{safe_reason}'\""
        )
        cmd_out = (
            f'powershell.exe -Command "New-NetFirewallRule '
            f"-DisplayName '{rule_name}_OUT' -Direction Outbound -Action Block "
            f"-RemoteAddress {ip_address} -Description '{safe_reason}'\""
        )
        res_in  = subprocess.run(cmd_in,  shell=True, capture_output=True, text=True)
        res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)  # noqa: F841

        # returncode 0 = created, "already exists" in stderr = idempotent success
        return res_in.returncode == 0 or "already exists" in res_in.stderr.lower()
    except Exception as exc:
        logger.error("Windows firewall error for %s: %s", ip_address, exc)
        return False


def block_ip_linux(ip_address: str, safe_reason: str) -> bool:
    """Linux implementation using iptables."""
    try:
        if subprocess.run("iptables --version", shell=True, capture_output=True).returncode != 0:
            logger.error("iptables not found on this Linux system.")
            return False

        for direction, flag in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            check = f"sudo iptables -C {direction} {flag} {ip_address} -j DROP"
            if subprocess.run(check, shell=True, capture_output=True).returncode != 0:
                add = (
                    f"sudo iptables -A {direction} {flag} {ip_address} -j DROP "
                    f"-m comment --comment '{safe_reason}'"
                )
                subprocess.run(add, shell=True)
        return True
    except Exception as exc:
        logger.error("Linux firewall error for %s: %s", ip_address, exc)
        return False


# ---------------------------------------------------------------------------
# Privilege check — evaluated ONCE at import time so we warn exactly once.
# ---------------------------------------------------------------------------

def _has_privileges() -> bool:
    """Return True if the process can modify OS firewall rules."""
    try:
        if sys.platform == "win32":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore
        return os.getuid() == 0
    except Exception:
        return False


_PRIVILEGES_OK: bool = _has_privileges()

if not _PRIVILEGES_OK:
    logger.warning(
        "⚠  NetScan is NOT running as Administrator / root. "
        "Automatic IP blocking is DISABLED — detection and alerting still work normally. "
        "To enable blocking: right-click your terminal → 'Run as Administrator' "
        "then restart with:  python cli.py capture"
    )


def block_ip(ip_address: str, reason: str = "High Risk Detection") -> bool:
    """
    Block *ip_address* at the OS firewall layer.

    Returns True if the rule was applied, False if skipped (insufficient
    privileges) or if the OS command failed.  Does NOT raise exceptions.
    """
    if not _PRIVILEGES_OK:
        # Already warned once at import — stay silent to avoid log spam.
        return False

    rule_name   = f"NetScan_Block_{ip_address}"
    safe_reason = reason.replace("'", "").replace('"', "")

    if sys.platform == "win32":
        success = block_ip_windows(ip_address, rule_name, safe_reason)
    else:
        success = block_ip_linux(ip_address, safe_reason)

    if success:
        logger.warning(
            "🚫 FIREWALL BLOCK APPLIED — %s blocked at OS layer. Reason: %s",
            ip_address, safe_reason,
        )
    else:
        logger.error(
            "Firewall block FAILED for %s — OS command returned an error. "
            "Ensure you are running as Administrator.", ip_address,
        )
    return success
