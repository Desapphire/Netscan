from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

from app.capture.types import PacketMeta


@dataclass(frozen=True)
class CaptureSettings:
    mode: str  # "live" | "pcap" | "dummy"
    interface: str | None = None
    pcap_path: str | None = None
    bpf_filter: str | None = None


def _norm_proto(p: str | None) -> str:
    if not p:
        return "other"
    p = p.lower()
    if p in {"tcp", "udp", "icmp"}:
        return p
    return "other"


class PacketSource:
    """
    Metadata-only packet source.

    - live: uses pyshark (requires tshark installed)
    - pcap: reads from a pcap file (also pyshark)
    - dummy: emits synthetic PacketMeta for local development
    """

    def __init__(self, settings: CaptureSettings):
        self.settings = settings

    def packets(self) -> Iterator[PacketMeta]:
        mode = (self.settings.mode or "dummy").lower()
        if mode == "dummy":
            yield from self._dummy_packets()
            return
        if mode in {"live", "pcap"}:
            yield from self._pyshark_packets()
            return
        raise ValueError(f"Unknown capture mode: {self.settings.mode}")

    def _pyshark_packets(self) -> Iterator[PacketMeta]:
        try:
            import pyshark  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "pyshark is not installed. Install it and ensure tshark is available, "
                "or use mode=dummy for MVP."
            ) from e

        if self.settings.mode == "live":
            if not self.settings.interface:
                raise ValueError("Live capture requires interface name (e.g., eth0).")
            capture = pyshark.LiveCapture(interface=self.settings.interface, bpf_filter=self.settings.bpf_filter)
        else:
            if not self.settings.pcap_path:
                raise ValueError("PCAP mode requires pcap_path.")
            capture = pyshark.FileCapture(self.settings.pcap_path, bpf_filter=self.settings.bpf_filter)

        for pkt in capture.sniff_continuously():
            try:
                if not hasattr(pkt, "ip"):
                    continue
                src_ip = str(pkt.ip.src)
                dst_ip = str(pkt.ip.dst)
                length_bytes = int(getattr(pkt, "length", 0) or 0)
                ts = float(getattr(pkt, "sniff_timestamp", time.time()))

                protocol = "other"
                src_port: Optional[int] = None
                dst_port: Optional[int] = None

                if hasattr(pkt, "tcp"):
                    protocol = "tcp"
                    src_port = int(pkt.tcp.srcport)
                    dst_port = int(pkt.tcp.dstport)
                elif hasattr(pkt, "udp"):
                    protocol = "udp"
                    src_port = int(pkt.udp.srcport)
                    dst_port = int(pkt.udp.dstport)
                elif hasattr(pkt, "icmp"):
                    protocol = "icmp"

                dns_query = None
                if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                    dns_query = str(pkt.dns.qry_name)

                tls_sni = None
                # Depending on tshark versions, SNI may appear under tls.handshake.extensions_server_name
                if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                    tls_sni = str(pkt.tls.handshake_extensions_server_name)

                yield PacketMeta(
                    ts=ts,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=_norm_proto(protocol),
                    src_port=src_port,
                    dst_port=dst_port,
                    length_bytes=length_bytes,
                    dns_query=dns_query,
                    tls_sni=tls_sni,
                )
            except Exception:
                # Skip malformed packets; keep capture running
                continue

    def _dummy_packets(self) -> Iterator[PacketMeta]:
        """
        Emits a repeating pattern: benign browsing + occasional VPN/torrent-like behavior.
        This keeps the rest of the pipeline testable without root or packet capture.
        """
        now = time.time()
        srcs = ["10.0.5.23", "10.0.5.99", "10.0.5.42"]

        i = 0
        while True:
            base_ts = now + i * 0.05
            # Benign HTTPS browsing (SNI)
            yield PacketMeta(
                ts=base_ts,
                src_ip=srcs[0],
                dst_ip="142.250.184.14",
                protocol="tcp",
                src_port=53000 + (i % 2000),
                dst_port=443,
                length_bytes=1200,
                tls_sni="accounts.google.com",
            )
            # DNS lookups that include gambling-like keywords sometimes
            if i % 40 == 0:
                yield PacketMeta(
                    ts=base_ts + 0.001,
                    src_ip=srcs[1],
                    dst_ip="10.0.0.2",
                    protocol="udp",
                    src_port=55000 + (i % 2000),
                    dst_port=53,
                    length_bytes=120,
                    dns_query="best-casino-bet.example",
                )
            # VPN-like UDP to 1194
            if i % 25 == 0:
                yield PacketMeta(
                    ts=base_ts + 0.002,
                    src_ip=srcs[2],
                    dst_ip="198.51.100.10",
                    protocol="udp",
                    src_port=60000 + (i % 1000),
                    dst_port=1194,
                    length_bytes=1400,
                )
            # Torrent-like TCP fanout
            if i % 60 == 0:
                for j in range(45):
                    yield PacketMeta(
                        ts=base_ts + 0.01 + j * 0.0005,
                        src_ip=srcs[1],
                        dst_ip=f"203.0.113.{(j % 200) + 1}",
                        protocol="tcp",
                        src_port=50000 + ((i + j) % 2000),
                        dst_port=6881,
                        length_bytes=1000,
                        tls_sni=None,
                    )

            i += 1

