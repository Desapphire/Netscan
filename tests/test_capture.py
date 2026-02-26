"""Tests for capture and packet source."""
from __future__ import annotations

import pytest

from app.capture.packet_source import CaptureSettings, PacketSource
from app.capture.types import PacketMeta


def test_dummy_packets_yield_packet_meta():
    """Dummy source should yield PacketMeta objects."""
    settings = CaptureSettings(mode="dummy")
    src = PacketSource(settings)
    packets = []
    for pkt in src.packets():
        packets.append(pkt)
        if len(packets) >= 20:
            break

    assert len(packets) == 20
    for p in packets:
        assert isinstance(p, PacketMeta)
        assert p.src_ip
        assert p.dst_ip
        assert p.protocol in {"tcp", "udp", "icmp", "other"}
        assert p.length_bytes > 0


def test_dummy_includes_multiple_sources():
    """Dummy source should produce packets from multiple simulated IPs."""
    settings = CaptureSettings(mode="dummy")
    src = PacketSource(settings)
    ips = set()
    for i, pkt in enumerate(src.packets()):
        ips.add(pkt.src_ip)
        if i > 200:
            break
    assert len(ips) >= 2, f"Expected multiple IPs, got {ips}"


def test_dummy_dns_and_tls():
    """Some dummy packets should have DNS queries or TLS SNI."""
    settings = CaptureSettings(mode="dummy")
    src = PacketSource(settings)
    has_dns = False
    has_tls = False
    for i, pkt in enumerate(src.packets()):
        if pkt.dns_query:
            has_dns = True
        if pkt.tls_sni:
            has_tls = True
        if has_dns and has_tls:
            break
        if i > 500:
            break
    assert has_dns, "Expected some DNS queries in dummy traffic"
    assert has_tls, "Expected some TLS SNI in dummy traffic"


def test_invalid_mode_raises():
    settings = CaptureSettings(mode="unknown_mode")
    src = PacketSource(settings)
    with pytest.raises(ValueError, match="Unknown capture mode"):
        list(src.packets())
