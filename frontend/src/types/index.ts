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
