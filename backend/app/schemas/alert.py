from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime

class AlertBase(BaseModel):
    title: str
    category: str
    severity: str = "HIGH"
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: str = "TCP"
    affected_asset_id: Optional[int] = None
    description: str
    raw_packet_hex: Optional[str] = None
    metadata_json: Dict[str, Any] = {}
    status: str = "ACTIVE"
    assigned_to: Optional[str] = None

class AlertCreate(AlertBase):
    pass

class AlertUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    description: Optional[str] = None

class AlertOut(AlertBase):
    id: int
    created_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class AlertStats(BaseModel):
    total_active: int
    critical_active: int
    high_active: int
    investigating: int
    resolved_today: int
