from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, Iterator, List

from app.capture.flow_aggregator import FlowAggregator
from app.capture.packet_source import CaptureSettings, PacketSource
from app.capture.types import PacketMeta
from app.config import load_config


@dataclass(frozen=True)
class CaptureOutput:
    window_start_ts: float
    window_end_ts: float
    packets: list[PacketMeta]


def run_capture_loop(
    *,
    mode: str = "scapy",
    interface: str | None = None,
    bpf_filter: str | None = None,
) -> Iterator[CaptureOutput]:
    """
    Sliding-window capture yielding PacketMeta batches every slide interval.

    This is the “scanning part” (metadata capture) in MVP form.
    """
    cfg = load_config().raw
    window_s = int(cfg["app"]["window_seconds"])
    slide_s = int(cfg["app"]["slide_seconds"])

    settings = CaptureSettings(mode=mode, interface=interface, bpf_filter=bpf_filter)
    src = PacketSource(settings)

    buf: Deque[PacketMeta] = deque()
    window_start = time.time()
    next_emit = window_start + slide_s

    for pkt in src.packets():
        now = time.time()
        buf.append(pkt)

        # Drop old packets
        cutoff = now - window_s
        while buf and buf[0].ts < cutoff:
            buf.popleft()

        if now >= next_emit:
            window_end = now
            window_start_ts = window_end - window_s
            batch = [p for p in buf if window_start_ts <= p.ts < window_end]
            yield CaptureOutput(window_start_ts=window_start_ts, window_end_ts=window_end, packets=batch)
            next_emit = now + slide_s

