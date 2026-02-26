from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, Iterator, List, Set, Tuple

from app.capture.types import PacketMeta
from app.features.feature_types import FeatureVector


@dataclass
class _DeviceWindow:
    src_ip: str
    ts_first: float
    ts_last: float

    bytes_sent: int = 0
    bytes_received: int = 0

    packet_sizes: List[int] = None  # type: ignore
    packet_times: List[float] = None  # type: ignore

    dst_ips: Set[str] = None  # type: ignore
    dst_ports: Set[int] = None  # type: ignore
    domains: Set[str] = None  # type: ignore

    tcp_flows: int = 0
    udp_flows: int = 0
    dns_queries: int = 0

    def __post_init__(self) -> None:
        self.packet_sizes = []
        self.packet_times = []
        self.dst_ips = set()
        self.dst_ports = set()
        self.domains = set()


def _mean_std(xs: List[float]) -> tuple[float, float]:
    if not xs:
        return 0.0, 0.0
    m = sum(xs) / len(xs)
    if len(xs) < 2:
        return float(m), 0.0
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return float(m), float(math.sqrt(var))


class FlowAggregator:
    """
    Aggregates PacketMeta into per-device FeatureVector for a fixed window.

    MVP assumptions:
    - We treat packets as "sent" from src_ip perspective.
    - Received bytes are not reliably known without full bidirectional modeling; we approximate 0 unless inferred.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = int(window_seconds)

    def aggregate_window(
        self,
        packets: Iterable[PacketMeta],
        window_start_ts: float,
        window_end_ts: float,
    ) -> list[FeatureVector]:
        by_src: Dict[str, _DeviceWindow] = {}
        flows_per_src: Dict[str, Set[Tuple[str, str, int | None]]] = defaultdict(set)

        for p in packets:
            if p.ts < window_start_ts or p.ts >= window_end_ts:
                continue

            w = by_src.get(p.src_ip)
            if w is None:
                w = _DeviceWindow(src_ip=p.src_ip, ts_first=p.ts, ts_last=p.ts)
                by_src[p.src_ip] = w
            else:
                w.ts_last = max(w.ts_last, p.ts)

            w.bytes_sent += int(p.length_bytes)
            w.packet_sizes.append(int(p.length_bytes))
            w.packet_times.append(float(p.ts))
            w.dst_ips.add(p.dst_ip)
            if p.dst_port is not None:
                w.dst_ports.add(int(p.dst_port))

            if p.protocol == "tcp":
                w.tcp_flows += 1
            elif p.protocol == "udp":
                w.udp_flows += 1

            if p.dns_query:
                w.dns_queries += 1
                w.domains.add(p.dns_query)
            if p.tls_sni:
                w.domains.add(p.tls_sni)

            flows_per_src[p.src_ip].add((p.dst_ip, p.protocol, p.dst_port))

        fvs: list[FeatureVector] = []
        from datetime import datetime, timezone

        ws_dt = datetime.fromtimestamp(window_start_ts, tz=timezone.utc).replace(tzinfo=None)
        we_dt = datetime.fromtimestamp(window_end_ts, tz=timezone.utc).replace(tzinfo=None)

        for src_ip, w in by_src.items():
            sizes = [float(s) for s in w.packet_sizes]
            mean_size, std_size = _mean_std(sizes)

            # inter-arrival times
            times = sorted(w.packet_times)
            inter = [times[i] - times[i - 1] for i in range(1, len(times))]
            mean_iat, std_iat = _mean_std([float(x) for x in inter])

            observed_ports = sorted(list(w.dst_ports))
            top_port = observed_ports[0] if observed_ports else None

            fv = FeatureVector(
                window_start=ws_dt,
                window_end=we_dt,
                src_ip=src_ip,
                num_flows=len(flows_per_src.get(src_ip, set())),
                num_unique_dst_ips=len(w.dst_ips),
                num_unique_domains=len(w.domains),
                total_bytes_sent=w.bytes_sent,
                total_bytes_received=w.bytes_received,
                avg_packet_size=mean_size,
                std_packet_size=std_size,
                avg_inter_packet_time=mean_iat,
                std_inter_packet_time=std_iat,
                tcp_flow_count=w.tcp_flows,
                udp_flow_count=w.udp_flows,
                dns_query_count=w.dns_queries,
                distinct_dst_ports=len(w.dst_ports),
                top_port=top_port,
                ratio_known_vpn_ips=0.0,
                ratio_known_restricted_domains=0.0,
                extra={
                    "observed_dst_ports": observed_ports,
                    "observed_domains": sorted(list(w.domains))[:50],
                },
            )
            fvs.append(fv)

        return fvs

