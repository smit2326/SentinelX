from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any
from datetime import datetime

class AuditLogCreate(BaseModel):
    actor_id: Optional[int] = None
    actor_email: str
    actor_role: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    status: str = "SUCCESS"
    ip_address: str = "127.0.0.1"
    user_agent: Optional[str] = None
    details: Dict[str, Any] = {}

class AuditLogOut(BaseModel):
    id: int
    timestamp: datetime
    actor_id: Optional[int] = None
    actor_email: str
    actor_role: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    status: str
    ip_address: str
    user_agent: Optional[str] = None
    details: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)
