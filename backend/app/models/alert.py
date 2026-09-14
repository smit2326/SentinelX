from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from datetime import datetime, timezone
import enum
from app.core.database import Base

class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AlertStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False) # e.g. Traffic Anomaly, Port Scan, IoT Rogue Traffic, CVE Exploit Attempt
    severity = Column(String(20), default=AlertSeverity.HIGH.value, nullable=False)
    
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    protocol = Column(String(20), default="TCP") # TCP, UDP, ICMP, HTTP, RTSP
    
    affected_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    description = Column(Text, nullable=False)
    raw_packet_hex = Column(Text, nullable=True) # PCAP hex dump or telemetry payload snippet
    metadata_json = Column(JSON, default=dict)
    
    status = Column(String(30), default=AlertStatus.ACTIVE.value, nullable=False)
    assigned_to = Column(String(100), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    resolved_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<Alert #{self.id} [{self.severity}] {self.title}>"
