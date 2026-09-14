from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service: str
    state: str = "open"
    version: Optional[str] = None

class ServiceInfo(BaseModel):
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None

class AssetBase(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str = "Workstation"
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: List[Dict[str, Any]] = []
    services: List[Dict[str, Any]] = []
    is_iot: bool = False
    is_cctv: bool = False
    firmware_version: Optional[str] = None
    cctv_stream_protocol: Optional[str] = None
    risk_score: float = 0.0
    status: str = "Online"
    is_quarantined: bool = False
    location: str = "HQ Datacenter"
    subnet: str = "192.168.1.0/24"

class AssetCreate(AssetBase):
    pass

class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: Optional[List[Dict[str, Any]]] = None
    services: Optional[List[Dict[str, Any]]] = None
    is_iot: Optional[bool] = None
    is_cctv: Optional[bool] = None
    firmware_version: Optional[str] = None
    cctv_stream_protocol: Optional[str] = None
    risk_score: Optional[float] = None
    status: Optional[str] = None
    is_quarantined: Optional[bool] = None
    location: Optional[str] = None
    subnet: Optional[str] = None

class AssetOut(AssetBase):
    id: int
    last_scanned: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ScanRequest(BaseModel):
    target_subnet: str = "192.168.1.0/24"
    scan_type: str = "full"
    custom_ports: Optional[str] = None
