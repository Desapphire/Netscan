import sys
import os
import subprocess
import logging

def block_ip_windows(ip_address: str, rule_name: str, safe_reason: str) -> bool:
    """Windows implementation using PowerShell."""
    try:
        # We attempt to add both Inbound and Outbound rules to strictly cut off communication.
        cmd_in = f'powershell.exe -Command "New-NetFirewallRule -DisplayName \'{rule_name}_IN\' -Direction Inbound -Action Block -RemoteAddress {ip_address} -Description \'{safe_reason}\'"'
        cmd_out = f'powershell.exe -Command "New-NetFirewallRule -DisplayName \'{rule_name}_OUT\' -Direction Outbound -Action Block -RemoteAddress {ip_address} -Description \'{safe_reason}\'"'
        
        res_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
        res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
        
        if res_in.returncode == 0 or "already exists" in res_in.stderr:
            return True
        return False
    except Exception as e:
        logger.error(f"Windows firewall error: {e}")
        return False

def block_ip_linux(ip_address: str, safe_reason: str) -> bool:
    """Linux implementation using iptables."""
    try:
        # Check if iptables exists
        check_cmd = "iptables --version"
        if subprocess.run(check_cmd, shell=True, capture_output=True).returncode != 0:
            logger.error("iptables not found on this Linux system.")
            return False

        # Add rule to INPUT and OUTPUT chains
        # Use -C to check if it already exists to avoid duplicates
        check_in = f"sudo iptables -C INPUT -s {ip_address} -j DROP"
        if subprocess.run(check_in, shell=True, capture_output=True).returncode != 0:
            cmd_in = f"sudo iptables -A INPUT -s {ip_address} -j DROP -m comment --comment '{safe_reason}'"
            subprocess.run(cmd_in, shell=True)

        check_out = f"sudo iptables -C OUTPUT -d {ip_address} -j DROP"
        if subprocess.run(check_out, shell=True, capture_output=True).returncode != 0:
            cmd_out = f"sudo iptables -A OUTPUT -d {ip_address} -j DROP -m comment --comment '{safe_reason}'"
            subprocess.run(cmd_out, shell=True)

        return True
    except Exception as e:
        logger.error(f"Linux firewall error: {e}")
        return False

def block_ip(ip_address: str, reason: str = "High Risk Detection") -> bool:
    """
    Blocks an IP address globally using the OS-specific firewall.
    Requires Administrator/Root privileges.
    """
    rule_name = f"NetScan_Block_{ip_address}"
    safe_reason = reason.replace("'", "").replace('"', "")
    
    success = False
    if sys.platform == "win32":
        success = block_ip_windows(ip_address, rule_name, safe_reason)
    else:
        success = block_ip_linux(ip_address, safe_reason)

    if success:
        logger.warning(f"\u26A0\uFE0F FIREWALL BLOCK APPLIED \u26A0\uFE0F {ip_address} blocked at OS layer.")
        return True
    else:
        logger.error(f"Failed to apply firewall block for {ip_address}. Check privileges.")
        return False

