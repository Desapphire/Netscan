"""Centralized pipeline logic for processing captured packet windows."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.capture.capture_runner import CaptureOutput
from app.db.models import Detection, Device, NetworkFeature
from app.features.feature_types import FeatureVector
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_extractor import FeatureExtractor
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.detection.dns_intelligence import DNSIntelligenceModule
from app.blocking.firewall import block_ip
from app.utils.time_utils import utcnow

logger = logging.getLogger("netscan.pipeline")

class ProcessingPipeline:
    def __init__(self, window_seconds: int):
        self.dns_intel = DNSIntelligenceModule()
        self.extractor = FeatureExtractor(window_seconds, dns_intel=self.dns_intel)
        self.detector = HybridDetector()
        self.ai_logic = AIDecisionLogic()
        self.alert_mgr = AlertManager()
        self.notifier = Notifier()

    def process_window(self, session: Session, capture_out: CaptureOutput) -> dict[str, Any]:
        """
        Process a single window of captured packets:
        1. Extract Features
        2. DNS Intelligence Analysis & Alerting
        3. ML/Rules Detection
        4. Alert Creation & Notification
        5. Device Persistence
        """
        window_packets = len(capture_out.packets)
        window_bytes = sum(p.length_bytes for p in capture_out.packets)

        # 1. Feature Extraction
        fvs = self.extractor.extract(
            capture_out.packets,
            capture_out.window_start_ts,
            capture_out.window_end_ts,
        )

        # 2. DNS Intelligence Analysis
        unique_queries = set()
        for p in capture_out.packets:
            if p.dns_query:
                unique_queries.add((p.src_ip, p.dns_query))
        
        dns_alerts = 0
        for src_ip, domain in unique_queries:
            try:
                dns_result = self.dns_intel.analyze_query(src_ip, domain)
                if dns_result["category"] != "normal":
                    alert_title = f"Restricted DNS Activity: {dns_result['category'].upper()}"
                    alert_summary = (
                        f"Device {src_ip} queried restricted domain: {domain}. "
                        f"Resolved IP: {dns_result['resolved_ip']}. Reason: {dns_result['reason']}"
                    )
                    risk_sev = "high" if dns_result["risk_score"] > 0.7 else "medium"
                    self.notifier.notify(alert_title, alert_summary, risk_sev)
                    logger.warning("DNS INTEL ALERT: %s - %s", alert_title, alert_summary)
                    dns_alerts += 1
                    
                    if risk_sev == "high":
                        block_ip(src_ip, f"DNS IPS: {alert_title}")
            except Exception as e:
                logger.error("Error in DNS intelligence analysis for %s: %s", domain, e)

        # 3. Detection & Persistence
        alerts_created = 0
        active_ips = []

        for fv in fvs:
            active_ips.append(fv.src_ip)

            # Persist Feature
            nf = self.alert_mgr.persist_feature(session, fv)
            
            # Run Detection (pass session for risk boosting)
            dr = self.detector.detect(fv, session=session)
            
            # Persist Detection Result
            det = self.alert_mgr.persist_detection(session, fv, dr, nf.id)

            if dr.decision == "allow":
                logger.debug(
                    "  %s → risk=%.2f (allow) rule=%.2f ml=%.2f conf=%.2f",
                    fv.src_ip, dr.combined_risk, dr.rule_score, dr.ml_score, dr.ml_confidence,
                )
            else:
                boost_tag = " [BOOSTED]" if dr.boosted else ""
                top = ", ".join(f"{n}={v:.2f}" for n, v in dr.top_features[:2])
                corr = list(dr.correlation_hits.keys())
                logger.warning(
                    "  ⚠ %s → risk=%.2f (%s) rule=%.2f ml=%.2f conf=%.2f%s %s%s%s",
                    fv.src_ip, dr.combined_risk, dr.decision,
                    dr.rule_score, dr.ml_score, dr.ml_confidence, boost_tag,
                    f"[{dr.guessed_threat_type}] " if dr.guessed_threat_type else "",
                    f"corr={corr} " if corr else "",
                    f"top={top}" if top else "",
                )

            # AI Review Escalation
            ai_result = None
            ai_id = None
            if self.ai_logic.should_escalate(dr):
                ai_result = self.ai_logic.assess_sync(fv, dr)
                ai_obj = self.alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            # Create Alert if suspicious
            if dr.decision != "allow":
                alert = self.alert_mgr.create_alert(
                    session, fv, dr, det.id,
                    ai=ai_result, ai_assessment_id=ai_id,
                )
                self.notifier.notify(alert.title, alert.summary, alert.severity)
                alerts_created += 1
                
                if alert.severity in ("high", "critical"):
                    block_ip(fv.src_ip, f"ML IPS: {alert.title}")

            # Update Device table
            device = session.query(Device).filter(Device.ip_address == fv.src_ip).first()
            if device:
                device.last_seen = utcnow()
            else:
                session.add(Device(ip_address=fv.src_ip, last_seen=utcnow()))

        return {
            "packets": window_packets,
            "bytes": window_bytes,
            "fvs_count": len(fvs),
            "alerts_count": alerts_created + dns_alerts,
            "active_ips": active_ips,
        }

    def run_batch_detection(self, session: Session, limit: int = 100) -> int:
        """Process unprocessed NetworkFeature rows."""
        unprocessed = (
            session.query(NetworkFeature)
            .outerjoin(Detection, NetworkFeature.id == Detection.feature_id)
            .filter(Detection.id == None)
            .order_by(desc(NetworkFeature.window_start))
            .limit(limit)
            .all()
        )
        
        if not unprocessed:
            return 0
            
        logger.info("Found %d unprocessed features. Starting catch-up batch.", len(unprocessed))
        processed = 0
        for nf in unprocessed:
            fv = FeatureVector(
                src_ip=nf.src_ip,
                window_start=nf.window_start,
                duration=nf.duration,
                num_packets=nf.num_packets,
                num_flows=nf.num_flows,
                total_bytes_sent=nf.total_bytes_sent,
                total_bytes_received=nf.total_bytes_received,
                num_unique_dst_ips=nf.num_unique_dst_ips,
                tcp_flow_count=nf.tcp_flow_count,
                udp_flow_count=nf.udp_flow_count,
                dns_query_count=nf.dns_query_count,
                distinct_dst_ports=nf.distinct_dst_ports,
                top_port=nf.top_port,
                ratio_known_vpn_ips=nf.ratio_known_vpn_ips,
                ratio_known_restricted_domains=nf.ratio_known_restricted_domains,
                extra=nf.extra or {},
            )
            
            dr = self.detector.detect(fv)
            det = self.alert_mgr.persist_detection(session, fv, dr, nf.id)
            
            ai_result = None
            ai_id = None
            if self.ai_logic.should_escalate(dr):
                ai_result = self.ai_logic.assess_sync(fv, dr)
                ai_obj = self.alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            if dr.decision != "allow":
                alert = self.alert_mgr.create_alert(session, fv, dr, det.id, ai=ai_result, ai_assessment_id=ai_id)
                self.notifier.notify(alert.title, alert.summary, alert.severity)
                
                if alert.severity in ("high", "critical"):
                    block_ip(fv.src_ip, f"Batch ML IPS: {alert.title}")
            
            processed += 1
        
        return processed
