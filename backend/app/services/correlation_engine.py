from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import random
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.logger import logger
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.network import (
    NetworkCapture,
    NetworkPacketEvent,
    NetworkConnection,
    CorrelatedFinding
)

THREAT_RULES = [
    {
        "id": "RULE-001",
        "name": "Unexpected External Connection",
        "description": "Restricted internal asset (IoT, CCTV, or DB server) established direct outbound communication to an external public IP address.",
        "category": "Network Behavior Indicator",
        "severity": "HIGH"
    },
    {
        "id": "RULE-002",
        "name": "Unexpected Service Communication",
        "description": "Device initiated network traffic using a protocol or service outside its configured operational baseline.",
        "category": "Network Behavior Indicator",
        "severity": "MEDIUM"
    },
    {
        "id": "RULE-003",
        "name": "Repeated Connection Probes",
        "description": "Burst of repeated SYN attempts or unanswered probes indicating reconnaissance or port scanning.",
        "category": "Threat Indicator",
        "severity": "HIGH"
    },
    {
        "id": "RULE-004",
        "name": "Unusual Protocol Usage",
        "description": "Traffic observed on unusual destination port for the specified protocol.",
        "category": "Network Behavior Indicator",
        "severity": "MEDIUM"
    },
    {
        "id": "RULE-005",
        "name": "Unexpected Destination Port",
        "description": "Outbound connection directed to high-risk non-standard administrative or remote access port.",
        "category": "Threat Indicator",
        "severity": "HIGH"
    },
    {
        "id": "RULE-006",
        "name": "Lateral Movement Service Spike",
        "description": "Abnormal volume of authentication or file share service requests between internal workstation and critical infrastructure.",
        "category": "Threat Indicator",
        "severity": "CRITICAL"
    }
]

async def execute_correlation_engine(db: AsyncSession, capture_id: str) -> List[CorrelatedFinding]:
    """
    Correlates Phase 1 discovered assets (IP, OS, Firmware, Open Ports, CVEs)
    with Phase 2 parsed network packets and connections.
    """
    logger.info(f"Executing SENTINEL-X Correlation Engine on capture {capture_id}...")

    # Load capture metadata
    cap_res = await db.execute(select(NetworkCapture).where(NetworkCapture.capture_id == capture_id))
    capture = cap_res.scalars().first()
    if not capture:
        
        return []

    # Load packets & connections for this capture
    pkts_res = await db.execute(select(NetworkPacketEvent).where(NetworkPacketEvent.capture_id == capture_id))
    packets = pkts_res.scalars().all()

    conns_res = await db.execute(select(NetworkConnection).where(NetworkConnection.capture_id == capture_id))
    connections = conns_res.scalars().all()

    # Load all Phase 1 assets & vulnerabilities
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()
    asset_by_ip = {a.ip_address: a for a in assets}

    vulns_res = await db.execute(select(Vulnerability))
    vulns = vulns_res.scalars().all()
    vulns_by_asset = {}
    for v in vulns:
        vulns_by_asset.setdefault(v.affected_asset_id, []).append(v)

    new_findings: List[CorrelatedFinding] = []

    # 1. Check for unexpected external connections from IoT / CCTV / Servers (RULE-001)
    for conn in connections:
        if conn.is_external and conn.source_ip in asset_by_ip:
            asset = asset_by_ip[conn.source_ip]
            
            # Find matching packets for frame evidence
            frame_nums = [
                p.frame_number for p in packets
                if p.source_ip == conn.source_ip and p.destination_ip == conn.destination_ip
            ]
            frame_evidence_str = (
                f"Frames #{min(frame_nums)} - #{max(frame_nums)}" if frame_nums else "Frame #1"
            )

            # Check if this asset has known vulnerabilities (Module 10: Vulnerability + Traffic Correlation)
            asset_vulns = vulns_by_asset.get(asset.id, [])
            matching_vuln = None
            for v in asset_vulns:
                # Correlate CVE with affected port or service
                if v.port_affected and (v.port_affected == conn.destination_port or v.port_affected == conn.source_port):
                    matching_vuln = v
                    break
                elif "RTSP" in v.title or "Camera" in v.title or "Web" in v.title:
                    matching_vuln = v
                    break

            alert_code = f"ALT-00{random.randint(100, 999)}"
            
            if matching_vuln:
                # Correlated Security Finding (Module 10)
                finding = CorrelatedFinding(
                    alert_code=alert_code,
                    rule_id="RULE-001",
                    title=f"Vulnerability + Traffic Correlation: {asset.hostname or asset.device_type} Unexpected External Egress",
                    category="Vulnerability + Traffic Correlation",
                    severity="CRITICAL" if matching_vuln.cvss_score >= 9.0 else "HIGH",
                    affected_asset_id=asset.id,
                    source_ip=conn.source_ip,
                    destination_ip=conn.destination_ip,
                    protocol=conn.protocol,
                    destination_port=conn.destination_port,
                    observation=f"Observed unexpected external connection from internal {asset.device_type} to destination {conn.destination_ip}:{conn.destination_port}.",
                    correlation_explanation=(
                        f"Asset '{asset.hostname or asset.device_type}' (IP: {asset.ip_address}, Firmware: {asset.firmware_version or 'N/A'}) "
                        f"has known vulnerability {matching_vuln.cve_id} ({matching_vuln.title}). "
                        f"Network traffic observed active outbound connection to external IP {conn.destination_ip} on port {conn.destination_port}. "
                        f"Correlation indicates possible post-exploitation callback or unauthorized remote management channel. Evidence preserved in PCAP."
                    ),
                    cve_id=matching_vuln.cve_id,
                    evidence_pcap=capture.filename,
                    evidence_frames=frame_evidence_str,
                    status="NEW"
                )
            else:
                # Network Behavior Indicator (Module 8 & 9)
                finding = CorrelatedFinding(
                    alert_code=alert_code,
                    rule_id="RULE-001",
                    title=f"Network Behavior Indicator: Unexpected External Connection ({asset.hostname or asset.ip_address})",
                    category="Network Behavior Indicator",
                    severity="HIGH" if (asset.is_cctv or asset.is_iot) else "MEDIUM",
                    affected_asset_id=asset.id,
                    source_ip=conn.source_ip,
                    destination_ip=conn.destination_ip,
                    protocol=conn.protocol,
                    destination_port=conn.destination_port,
                    observation=f"New external destination {conn.destination_ip} observed communicating with internal asset {asset.ip_address}.",
                    correlation_explanation=(
                        f"Asset '{asset.hostname or asset.device_type}' is an internal {asset.device_type} with role '{asset.vendor or 'Host'}'. "
                        f"Operational baseline expects internal traffic only. Observed outbound communication to public internet IP {conn.destination_ip}. "
                        f"Indicator generated for analyst review to verify if connection is legitimate cloud telemetry or unapproved egress."
                    ),
                    cve_id=None,
                    evidence_pcap=capture.filename,
                    evidence_frames=frame_evidence_str,
                    status="NEW"
                )

            db.add(finding)
            new_findings.append(finding)

    # 2. Check for Lateral Kerberos/SMB anomalies dynamically on servers (RULE-006)
    server_asset = next((a for a in assets if "server" in (a.device_type or "").lower() or "server" in (a.hostname or "").lower()), None)
    kerb_smb_packets = [
        p for p in packets
        if p.protocol in ["SMB", "Kerberos"] and server_asset and p.destination_ip == server_asset.ip_address
    ]
    if len(kerb_smb_packets) >= 5 and server_asset:
        target_asset = server_asset
        target_vulns = vulns_by_asset.get(target_asset.id, []) if target_asset else []
        zerologon = next((v for v in target_vulns if "1472" in v.cve_id or "Netlogon" in v.title), None)
        
        frame_str = f"Frames #{kerb_smb_packets[0].frame_number} - #{kerb_smb_packets[-1].frame_number}"
        finding = CorrelatedFinding(
            alert_code=f"ALT-00{random.randint(100, 999)}",
            rule_id="RULE-006",
            title="Lateral Movement Indicator: High-Volume Active Directory Service Traffic",
            category="Vulnerability + Traffic Correlation" if zerologon else "Threat Indicator",
            severity="CRITICAL" if zerologon else "HIGH",
            affected_asset_id=target_asset.id if target_asset else None,
            source_ip=kerb_smb_packets[0].source_ip,
            destination_ip=target_asset.ip_address,
            protocol="SMB / Kerberos",
            destination_port=445,
            observation=f"Observed burst of Kerberos authentication and SMB tree connect requests towards {target_asset.hostname or target_asset.ip_address}.",
            correlation_explanation=(
                f"Host ({target_asset.ip_address}) hosts network directory/file services. "
                + (f"Correlated with open vulnerability {zerologon.cve_id}. " if zerologon else "")
                + f"Observed {len(kerb_smb_packets)} rapid transaction packets from host {kerb_smb_packets[0].source_ip}. "
                + "Analyst investigation recommended in Wireshark to verify ticket encryption types and RPC calls."
            ),
            cve_id=zerologon.cve_id if zerologon else None,
            evidence_pcap=capture.filename,
            evidence_frames=frame_str,
            status="NEW"
        )
        db.add(finding)
        new_findings.append(finding)

    await db.commit()
    logger.info(f"Correlation Engine completed for {capture_id}: Generated {len(new_findings)} security findings.")
    return new_findings


async def get_device_correlations(db: AsyncSession) -> List[Dict[str, Any]]:
    """
    Module 6 & 7: Connects Phase 1 Assets with Phase 2 Traffic flows & CVEs.
    Returns structured data for the Device Correlation View.
    """
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()

    vulns_res = await db.execute(select(Vulnerability))
    vulns = vulns_res.scalars().all()
    vulns_map = {}
    for v in vulns:
        vulns_map.setdefault(v.affected_asset_id, []).append(v)

    conns_res = await db.execute(select(NetworkConnection))
    all_conns = conns_res.scalars().all()

    correlations = []
    for asset in assets:
        asset_conns = [c for c in all_conns if c.source_ip == asset.ip_address or c.destination_ip == asset.ip_address]
        asset_vulns = vulns_map.get(asset.id, [])

        internal_traffic = [c for c in asset_conns if not c.is_external]
        external_traffic = [c for c in asset_conns if c.is_external]
        protocols_seen = list(set(c.protocol for c in asset_conns))

        correlations.append({
            "asset_id": asset.id,
            "ip_address": asset.ip_address,
            "hostname": asset.hostname,
            "device_type": asset.device_type,
            "vendor": asset.vendor,
            "os_name": asset.os_name,
            "os_version": asset.os_version,
            "firmware_version": asset.firmware_version,
            "open_ports": asset.open_ports or [],
            "risk_score": asset.risk_score,
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "status": v.status
                }
                for v in asset_vulns
            ],
            "network_activity": {
                "total_flows": len(asset_conns),
                "protocols": protocols_seen,
                "has_external_communication": len(external_traffic) > 0,
                "external_destinations": list(set(c.destination_ip for c in external_traffic if c.source_ip == asset.ip_address)),
                "internal_peers": list(set(c.destination_ip if c.source_ip == asset.ip_address else c.source_ip for c in internal_traffic)),
                "total_packets": sum(c.packet_count for c in asset_conns),
                "total_bytes": sum(c.byte_count for c in asset_conns)
            }
        })

    return correlations
