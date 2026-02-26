from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(20), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(200), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class NetworkFeature(Base):
    __tablename__ = "network_features"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime, index=True)

    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    dst_category: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    num_flows: Mapped[int] = mapped_column(Integer, default=0)
    num_unique_dst_ips: Mapped[int] = mapped_column(Integer, default=0)
    num_unique_domains: Mapped[int] = mapped_column(Integer, default=0)

    total_bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes_received: Mapped[int] = mapped_column(Integer, default=0)

    avg_packet_size: Mapped[float] = mapped_column(Float, default=0.0)
    std_packet_size: Mapped[float] = mapped_column(Float, default=0.0)

    avg_inter_packet_time: Mapped[float] = mapped_column(Float, default=0.0)
    std_inter_packet_time: Mapped[float] = mapped_column(Float, default=0.0)

    tcp_flow_count: Mapped[int] = mapped_column(Integer, default=0)
    udp_flow_count: Mapped[int] = mapped_column(Integer, default=0)

    dns_query_count: Mapped[int] = mapped_column(Integer, default=0)
    distinct_dst_ports: Mapped[int] = mapped_column(Integer, default=0)
    top_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    ratio_known_vpn_ips: Mapped[float] = mapped_column(Float, default=0.0)
    ratio_known_restricted_domains: Mapped[float] = mapped_column(Float, default=0.0)

    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    detections: Mapped[list["Detection"]] = relationship(back_populates="feature")


class Detection(Base):
    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feature_id: Mapped[int] = mapped_column(ForeignKey("network_features.id"), index=True)

    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime, index=True)

    rule_hits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    rule_score: Mapped[float] = mapped_column(Float, default=0.0)
    ml_score: Mapped[float] = mapped_column(Float, default=0.0)
    combined_risk: Mapped[float] = mapped_column(Float, default=0.0)

    decision: Mapped[str] = mapped_column(String(32), default="allow")  # allow|monitor|block|ai_review
    needs_ai: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    feature: Mapped["NetworkFeature"] = relationship(back_populates="detections")
    ai_assessment: Mapped["AIAssessment | None"] = relationship(back_populates="detection")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="detection")


class AIAssessment(Base):
    __tablename__ = "ai_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    detection_id: Mapped[int] = mapped_column(ForeignKey("detections.id"), index=True)

    threat_type: Mapped[str] = mapped_column(String(64), default="unknown")
    severity: Mapped[str] = mapped_column(String(16), default="low")  # low|medium|high|critical
    explanation: Mapped[str] = mapped_column(Text, default="")
    recommended_action: Mapped[str] = mapped_column(Text, default="")

    raw_response: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    detection: Mapped["Detection"] = relationship(back_populates="ai_assessment")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.id"), nullable=True, index=True)
    ai_assessment_id: Mapped[int | None] = mapped_column(
        ForeignKey("ai_assessments.id"), nullable=True, index=True
    )

    src_ip: Mapped[str] = mapped_column(String(64), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime, index=True)
    window_end: Mapped[datetime] = mapped_column(DateTime, index=True)

    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    threat_type: Mapped[str] = mapped_column(String(64))

    status: Mapped[str] = mapped_column(String(16), default="open")  # open|acknowledged|resolved
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    detection: Mapped["Detection | None"] = relationship(back_populates="alerts")

