from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

class CaptureStartRequest(BaseModel):
    interface: str = "eth0"
    duration_seconds: int = 60
    capture_filter: Optional[str] = None # e.g. "tcp port 80 or tcp port 443"
    max_packet_count: int = 50000
    max_file_size_mb: int = 50
    output_filename: Optional[str] = None
    capture_source: str = "TCPDump Local Monitor Point"

class CaptureStopRequest(BaseModel):
    capture_id: str

class NetworkCaptureOut(BaseModel):
    id: int
    capture_id: str
    filename: str
    interface: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: int
    packet_count: int
    file_size_bytes: int
    capture_source: str
    status: str
    filter_applied: Optional[str] = None
    file_path: Optional[str] = None
    metadata_json: Dict[str, Any] = {}
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class PacketEventOut(BaseModel):
    id: int
    capture_id: str
    frame_number: int
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_length: int
    tcp_flags: Optional[str] = None
    info: Optional[str] = None
    dns_query: Optional[str] = None
    tls_sni: Optional[str] = None
    is_external: bool = False
    raw_hex: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class NetworkConnectionOut(BaseModel):
    id: int
    capture_id: Optional[str] = None
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_count: int
    byte_count: int
    service_inferred: Optional[str] = None
    is_external: bool = False
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)

class CorrelatedFindingOut(BaseModel):
    id: int
    alert_code: str
    rule_id: str
    title: str
    category: str
    severity: str
    affected_asset_id: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: str
    destination_port: Optional[int] = None
    observation: str
    correlation_explanation: str
    cve_id: Optional[str] = None
    evidence_pcap: str
    evidence_frames: Optional[str] = None
    status: str
    analyst_conclusion: Optional[str] = None
    analyst_notes: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None
    
    # Associated asset details when populated
    asset_hostname: Optional[str] = None
    asset_device_type: Optional[str] = None
    asset_vendor: Optional[str] = None
    asset_os: Optional[str] = None
    asset_firmware: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class AnalystInvestigationRequest(BaseModel):
    status: str # NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE, BENIGN_ANOMALY
    analyst_conclusion: Optional[str] = None
    analyst_notes: Optional[str] = None
    assigned_to: Optional[str] = None

class TopDeviceStats(BaseModel):
    device_ip: str
    hostname: Optional[str] = None
    device_type: Optional[str] = "Unknown"
    packet_count: int
    byte_count: int
    connections: int
    role: str = "Host"

class TrafficOverviewStats(BaseModel):
    total_packets: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    unique_devices: int
    unique_destinations: int
    top_communicating_devices: List[TopDeviceStats]
    protocol_distribution: Dict[str, int]
    visibility_disclaimer: str

class NetworkInterfaceOut(BaseModel):
    name: str
    description: str
    ip_address: Optional[str] = None
    is_up: bool
    type: str
