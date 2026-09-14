from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from datetime import datetime, timezone
from app.core.database import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, index=True, nullable=False)
    mac_address = Column(String(50), nullable=True)
    hostname = Column(String(255), nullable=True)
    device_type = Column(String(100), default="Workstation", nullable=False) # Server, Workstation, IoT, CCTV Camera, Router, Firewall
    vendor = Column(String(100), nullable=True)
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    
    # Discovery & Network
    open_ports = Column(JSON, default=list) # e.g. [{"port": 80, "protocol": "tcp", "service": "http", "state": "open"}]
    services = Column(JSON, default=list)    # e.g. [{"name": "nginx", "version": "1.24.0", "banner": "nginx/1.24.0"}]
    
    # Specialized IoT / CCTV Attributes
    is_iot = Column(Boolean, default=False)
    is_cctv = Column(Boolean, default=False)
    firmware_version = Column(String(100), nullable=True)
    cctv_stream_protocol = Column(String(50), nullable=True) # RTSP, ONVIF, HTTP-FLV
    
    # Risk & Status
    risk_score = Column(Float, default=0.0) # 0.0 to 100.0
    status = Column(String(50), default="Online") # Online, Offline, Warning, Quarantined
    is_quarantined = Column(Boolean, default=False)
    
    # Metadata
    location = Column(String(100), default="HQ Datacenter")
    subnet = Column(String(50), default="192.168.1.0/24")
    last_scanned = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Asset {self.ip_address} ({self.hostname or self.device_type}) - Risk {self.risk_score}>"
