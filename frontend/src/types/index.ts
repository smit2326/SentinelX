export type UserRole = 'admin' | 'analyst' | 'auditor';

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  avatar_url?: string;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface PortInfo {
  port: number;
  protocol: string;
  service: string;
  state: string;
  version?: string;
}

export interface ServiceInfo {
  name: string;
  version?: string;
  banner?: string;
}

export interface Asset {
  id: number;
  ip_address: string;
  mac_address?: string;
  hostname?: string;
  device_type: string;
  vendor?: string;
  os_name?: string;
  os_version?: string;
  open_ports: PortInfo[];
  services: ServiceInfo[];
  is_iot: boolean;
  is_cctv: boolean;
  firmware_version?: string;
  cctv_stream_protocol?: string;
  risk_score: number;
  status: 'Online' | 'Offline' | 'Warning' | 'Quarantined';
  is_quarantined: boolean;
  location: string;
  subnet: string;
  last_scanned: string;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  cve_id: string;
  title: string;
  description: string;
  cvss_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  affected_asset_id?: number;
  affected_service?: string;
  port_affected?: number;
  remediation?: string;
  status: 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'FALSE_POSITIVE';
  exploit_available: string;
  discovered_at: string;
  resolved_at?: string;
}

export interface VulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  mitigated: number;
}

export interface Alert {
  id: number;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  source_ip?: string;
  destination_ip?: string;
  protocol: string;
  affected_asset_id?: number;
  description: string;
  raw_packet_hex?: string;
  metadata_json: Record<string, any>;
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
  assigned_to?: string;
  created_at: string;
  resolved_at?: string;
}

export interface AlertStats {
  total_active: number;
  critical_active: number;
  high_active: number;
  investigating: number;
  resolved_today: number;
}

export interface AuditLog {
  id: number;
  timestamp: string;
  actor_id?: number;
  actor_email: string;
  actor_role: string;
  action: string;
  resource: string;
  resource_id?: string;
  status: string;
  ip_address: string;
  user_agent?: string;
  details: Record<string, any>;
}

export interface SystemConfig {
  id: number;
  key: string;
  value: string;
  category: string;
  description?: string;
  is_secret: boolean;
  updated_at: string;
}

export interface DashboardTelemetry {
  timestamp: string;
  risk_summary: {
    overall_score: number;
    risk_level: string;
    grade: string;
    total_assets: number;
    quarantined: number;
    critical_assets: number;
    active_critical_alerts: number;
  };
  assets_summary: {
    total: number;
    online: number;
    quarantined: number;
    cctv_iot: number;
    distribution: Record<string, number>;
  };
  vulnerabilities_summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    mitigated: number;
  };
  recent_alerts: Alert[];
  active_alerts_count: number;
}

export interface ExecutiveReport {
  generated_at: string;
  platform_name: string;
  version: string;
  overall_risk_score: number;
  risk_level: string;
  risk_grade: string;
  total_assets: number;
  online_assets: number;
  quarantined_assets: number;
  cctv_iot_devices: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  mitigated_vulnerabilities: number;
  active_alerts: number;
  top_vulnerable_assets: Array<{
    id: number;
    ip_address: string;
    hostname: string;
    device_type: string;
    risk_score: number;
    is_quarantined: boolean;
    os: string;
  }>;
  recent_critical_alerts: Array<{
    id: number;
    title: string;
    category: string;
    severity: string;
    source_ip?: string;
    destination_ip?: string;
    created_at: string;
  }>;
  compliance_posture: Record<string, any>;
  remediation_recommendations: string[];
}

// Phase 2: Network Traffic, PCAP, and Correlation Engine Types
export interface NetworkInterface {
  name: string;
  description: string;
  ip_address?: string;
  is_up: boolean;
  type: string;
}

export interface NetworkCapture {
  id: number;
  capture_id: string;
  filename: string;
  interface: string;
  start_time: string;
  end_time?: string;
  duration_seconds: number;
  packet_count: number;
  file_size_bytes: number;
  capture_source: string;
  status: 'CAPTURING' | 'COMPLETED' | 'ANALYZED' | 'FAILED';
  filter_applied?: string;
  file_path?: string;
  metadata_json: Record<string, any>;
  created_at: string;
}

export interface PacketEvent {
  id: number;
  capture_id: string;
  frame_number: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port?: number;
  destination_port?: number;
  packet_length: number;
  tcp_flags?: string;
  info?: string;
  dns_query?: string;
  tls_sni?: string;
  is_external: boolean;
  raw_hex?: string;
}

export interface NetworkConnection {
  id: number;
  capture_id?: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port?: number;
  destination_port?: number;
  packet_count: number;
  byte_count: number;
  service_inferred?: string;
  is_external: boolean;
  first_seen: string;
  last_seen: string;
}

export interface TopDeviceStats {
  device_ip: string;
  hostname?: string;
  device_type?: string;
  packet_count: number;
  byte_count: number;
  connections: number;
  role: string;
}

export interface TrafficOverviewStats {
  total_packets: number;
  tcp_packets: number;
  udp_packets: number;
  icmp_packets: number;
  other_packets: number;
  unique_devices: number;
  unique_destinations: number;
  top_communicating_devices: TopDeviceStats[];
  protocol_distribution: Record<string, number>;
  visibility_disclaimer: string;
}

export interface CorrelatedFinding {
  id: number;
  alert_code: string;
  rule_id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  affected_asset_id?: number;
  source_ip?: string;
  destination_ip?: string;
  protocol: string;
  destination_port?: number;
  observation: string;
  correlation_explanation: string;
  cve_id?: string;
  evidence_pcap: string;
  evidence_frames?: string;
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE' | 'BENIGN_ANOMALY';
  analyst_conclusion?: string;
  analyst_notes?: string;
  assigned_to?: string;
  created_at: string;
  resolved_at?: string;
  asset_hostname?: string;
  asset_device_type?: string;
  asset_vendor?: string;
  asset_os?: string;
  asset_firmware?: string;
}

export interface DeviceCorrelation {
  asset_id: number;
  ip_address: string;
  hostname?: string;
  device_type: string;
  vendor?: string;
  os_name?: string;
  os_version?: string;
  firmware_version?: string;
  open_ports: PortInfo[];
  risk_score: number;
  vulnerabilities: Array<{
    cve_id: string;
    title: string;
    severity: string;
    cvss_score: number;
    status: string;
  }>;
  network_activity: {
    total_flows: number;
    protocols: string[];
    has_external_communication: boolean;
    external_destinations: string[];
    internal_peers: string[];
    total_packets: number;
    total_bytes: number;
  };
}

