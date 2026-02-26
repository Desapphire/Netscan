"""IP address utility helpers."""
from __future__ import annotations

import ipaddress
from typing import Iterable

# Well-known VPN provider IP ranges (sample – extend as needed)
_KNOWN_VPN_CIDRS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("198.51.100.0/24"),   # example VPN provider
    ipaddress.IPv4Network("203.0.113.0/24"),     # example VPN provider
]


def normalize_ip(ip: str) -> str:
    """Strip whitespace and normalise an IP string."""
    return str(ipaddress.ip_address(ip.strip()))


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC 1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def is_known_vpn_ip(ip: str, extra_ranges: Iterable[str] | None = None) -> bool:
    """Check if *ip* falls inside a known VPN provider range."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False

    for net in _KNOWN_VPN_CIDRS:
        if addr in net:
            return True

    if extra_ranges:
        for cidr in extra_ranges:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue

    return False


def compute_vpn_ratio(dst_ips: Iterable[str]) -> float:
    """Return the fraction of *dst_ips* that hit known VPN ranges."""
    ips = list(dst_ips)
    if not ips:
        return 0.0
    hits = sum(1 for ip in ips if is_known_vpn_ip(ip))
    return hits / len(ips)
