from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from datetime import datetime, timezone
from app.core.database import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    
    actor_id = Column(Integer, nullable=True)
    actor_email = Column(String(255), nullable=False, default="system")
    actor_role = Column(String(50), nullable=False, default="system")
    
    action = Column(String(100), nullable=False, index=True) # e.g. AUTH_LOGIN, ASSET_SCAN, ASSET_QUARANTINE, VULN_TRIAGE, CONFIG_UPDATE
    resource = Column(String(100), nullable=False) # e.g. auth, asset, vulnerability, alert, config, user
    resource_id = Column(String(100), nullable=True)
    
    status = Column(String(30), default="SUCCESS") # SUCCESS, FAILED, WARNING, BLOCKED
    ip_address = Column(String(50), default="127.0.0.1")
    user_agent = Column(String(255), nullable=True)
    details = Column(JSON, default=dict)

    def __repr__(self):
        return f"<AuditLog #{self.id} [{self.timestamp}] {self.actor_email} -> {self.action} ({self.status})>"
