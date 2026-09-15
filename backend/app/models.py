from typing import Optional
from sqlalchemy import String, Text, Boolean, Integer, Float, DateTime, ForeignKey, BigInteger, func
from sqlalchemy.orm import Mapped, mapped_column
try:
    from app.database import Base
except ImportError:
    from backend.app.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False) # e.g., 'ARP_SPOOF', 'DDOS_ANOMALY'
    details: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="INFO")
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, nullable=False)
    device_name: Mapped[str] = mapped_column(String(100), nullable=True)
    is_blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class TrafficMetric(Base):
    __tablename__ = "traffic_metrics"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    packet_count: Mapped[int] = mapped_column(Integer, nullable=False)
    bytes_transferred: Mapped[int] = mapped_column(Integer, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    recorded_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[Optional[str]] = mapped_column(String(50), default="Active", nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class AdminIncident(Base):
    __tablename__ = "admin_incidents"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    analyst: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    updated: Mapped[str] = mapped_column(String(50), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_origin: Mapped[str] = mapped_column(String(50), nullable=False)
    module: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    user_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    login_time: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    logout_time: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(String(255), nullable=False)

class AnalystActivityLog(Base):
    __tablename__ = "analyst_activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    user_role: Mapped[str] = mapped_column(String(50), default="Security Analyst")
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    module_name: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    threat_vector: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="NEW")
    analyst_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_source: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), default="TCP", nullable=True)
    abuse_score: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    created_by_user: Mapped[Optional[str]] = mapped_column(String(255), default="security@gmail.com", nullable=True)
    dataset_engine: Mapped[Optional[str]] = mapped_column(String(100), default="UNSW-NB15", nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class IncidentAction(Base):
    __tablename__ = "incident_actions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(50), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    old_value: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    new_value: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class UserActivityLog(Base):
    __tablename__ = "user_activity_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    dataset_engine: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class PcapSession(Base):
    __tablename__ = "pcap_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    total_packets: Mapped[int] = mapped_column(Integer, nullable=False)
    capture_size_bytes: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    analysis_status: Mapped[Optional[str]] = mapped_column(String(50), default="PROCESSED")
    uploaded_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class PcapPacket(Base):
    __tablename__ = "pcap_packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(Integer, ForeignKey("pcap_sessions.id", ondelete="CASCADE"), nullable=False)
    packet_number: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hex_dump: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ascii_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

class CapturedPacket(Base):
    __tablename__ = "captured_packets"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    flag_status: Mapped[Optional[str]] = mapped_column(String(50), default="Clean")
    threat_score: Mapped[Optional[float]] = mapped_column(Float, default=0.15)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, default=15)
    hex_dump: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ascii_payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    predicted_threat: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    threat_probability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    threat_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    anomaly_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class UserTrafficAnalysisState(Base):
    __tablename__ = "user_traffic_analysis_states"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), default="FILTER_APPLIED", nullable=False)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class EnterpriseThreatRecord(Base):
    __tablename__ = "enterprise_threat_records"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    user_email: Mapped[str] = mapped_column(String(255), index=True, nullable=False, default="security@gmail.com")
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="Investigating")
    action: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    engine: Mapped[Optional[str]] = mapped_column(String(100), default="AI-Neural-Probe")
    threat_score: Mapped[Optional[float]] = mapped_column(Float, default=0.0)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class CriticalAlert(Base):
    __tablename__ = "critical_alerts"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    user_email: Mapped[str] = mapped_column(String(255), index=True, nullable=False, default="security@gmail.com")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    priority: Mapped[str] = mapped_column(String(50), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(50), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(50), nullable=False)
    asset: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), default="TCP", nullable=True)
    dataset: Mapped[Optional[str]] = mapped_column(String(50), default="UNSW-NB15", nullable=True)
    risk_score: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    risk_score_val: Mapped[Optional[float]] = mapped_column(Float, default=85.0, nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="Investigating", nullable=False)
    action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    engine: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    affected_systems: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    analyst: Mapped[Optional[str]] = mapped_column(String(255), default="SOC Emergency Escalation Team", nullable=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class CriticalAlertAction(Base):
    __tablename__ = "critical_alert_actions"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(50), ForeignKey("critical_alerts.id", ondelete="CASCADE"), nullable=False)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    old_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    new_status: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())





