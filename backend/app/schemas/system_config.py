from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class SystemConfigBase(BaseModel):
    key: str
    value: str
    category: str = "general"
    description: Optional[str] = None
    is_secret: bool = False

class SystemConfigCreate(SystemConfigBase):
    pass

class SystemConfigUpdate(BaseModel):
    value: str
    description: Optional[str] = None

class SystemConfigOut(SystemConfigBase):
    id: int
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
