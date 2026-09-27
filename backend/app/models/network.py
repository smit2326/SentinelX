from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey, JSON
from datetime import datetime, timezone
import enum
from app.core.database import Base

class CaptureStatus(str, enum.Enum):
    CAPTURING = "CAPTURING"
    COMPLETED = "COMPLETED"
    ANALYZED = "ANALYZED"
    FAILED = "FAILED"

class NetworkCapture(Base):
    __tablename__ = "network_captures"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(50), unique=True, index=True, nullable=False) # e.g. CAP-00021
    filename = Column(String(255), nullable=False)                         # e.g. sentinel_2026_09_24_103000.pcap
    interface = Column(String(100), default="eth0", nullable=False)       # eth0, en0, SPAN-Port-01
    
    start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, default=60)
    
    packet_count = Column(Integer, default=0)
    file_size_bytes = Column(Integer, default=0)
    capture_source = Column(String(150), default="TCPDump Local Monitor Point") # TCPDump, SPAN Mirror, Manual Upload
    
    status = Column(String(30), default=CaptureStatus.COMPLETED.value, nullable=False)
    filter_applied = Column(String(255), nullable=True) # e.g. tcp port 80 or 443
    file_path = Column(String(500), nullable=True)
    
    metadata_json = Column(JSON, default=dict) # architecture visibility note, stats, etc.
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<NetworkCapture {self.capture_id} ({self.filename}) - {self.packet_count} pkts>"

class NetworkPacketEvent(Base):
    __tablename__ = "network_packet_events"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(50), index=True, nullable=False) # Refers to NetworkCapture.capture_id
    frame_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    source_ip = Column(String(50), nullable=False, index=True)
    destination_ip = Column(String(50), nullable=False, index=True)
    protocol = Column(String(30), nullable=False, index=True) # TCP, UDP, ICMP, DNS, TLS, HTTP, RTSP, SMB, ARP, MODBUS
    
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    packet_length = Column(Integer, default=64)
    tcp_flags = Column(String(50), nullable=True) # SYN, ACK, PSH, FIN, RST
    
    info = Column(Text, nullable=True) # Summary line (e.g. RTSP DESCRIBE, DNS Query corp.lan)
    dns_query = Column(String(255), nullable=True)
    tls_sni = Column(String(255), nullable=True)
    is_external = Column(Boolean, default=False)
    raw_hex = Column(Text, nullable=True) # First 64-128 bytes hex dump for deep packet inspector

    def __repr__(self):
        return f"<Packet #{self.frame_number} {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} [{self.protocol}]>"

class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    capture_id = Column(String(50), nullable=True, index=True)
    source_ip = Column(String(50), nullable=False, index=True)
    destination_ip = Column(String(50), nullable=False, index=True)
    protocol = Column(String(30), default="TCP")
    
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    
    packet_count = Column(Integer, default=1)
    byte_count = Column(Integer, default=0)
    service_inferred = Column(String(100), nullable=True) # e.g. RTSP, HTTPS, Kerberos, SMB
    
    is_external = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class CorrelatedFinding(Base):
    __tablename__ = "correlated_findings"

    id = Column(Integer, primary_key=True, index=True)
    alert_code = Column(String(50), unique=True, index=True, nullable=False) # e.g. ALT-00124
    rule_id = Column(String(50), nullable=False)                            # RULE-001, RULE-002, etc.
    title = Column(String(255), nullable=False)
    category = Column(String(100), default="Network Behavior Indicator")     # Network Behavior Indicator, Vulnerability + Traffic Correlation
    severity = Column(String(20), default="HIGH")                          # CRITICAL, HIGH, MEDIUM, LOW
    
    affected_asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    source_ip = Column(String(50), nullable=True)
    destination_ip = Column(String(50), nullable=True)
    protocol = Column(String(30), default="TCP")
    destination_port = Column(Integer, nullable=True)
    
    observation = Column(Text, nullable=False)
    correlation_explanation = Column(Text, nullable=False)
    cve_id = Column(String(50), nullable=True)                             # e.g. CVE-2021-36260
    
    evidence_pcap = Column(String(100), nullable=False)                    # e.g. CAP-00021.pcap
    evidence_frames = Column(String(100), nullable=True)                   # e.g. Frames #142 - #168
    
    status = Column(String(30), default="NEW")                             # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE, BENIGN_ANOMALY
    analyst_conclusion = Column(Text, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    resolved_at = Column(DateTime, nullable=True)
