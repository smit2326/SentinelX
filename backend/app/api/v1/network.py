import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.core.logger import logger
from app.models.user import User
from app.models.asset import Asset
from app.models.network import (
    NetworkCapture,
    NetworkPacketEvent,
    NetworkConnection,
    CorrelatedFinding,
    CaptureStatus
)
from app.schemas.network import (
    CaptureStartRequest,
    CaptureStopRequest,
    NetworkCaptureOut,
    PacketEventOut,
    NetworkConnectionOut,
    CorrelatedFindingOut,
    AnalystInvestigationRequest,
    TrafficOverviewStats,
    TopDeviceStats,
    NetworkInterfaceOut
)
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.audit_service import log_audit_event
from app.services.pcap_service import (
    PcapCaptureService,
    PCAP_STORAGE_DIR,
    VISIBILITY_DISCLAIMER
)
from app.services.correlation_engine import get_device_correlations

router = APIRouter(prefix="/network", tags=["Network Traffic, PCAP & TShark Analysis"])

# 1. Interface Management & Capture Visibility
@router.get("/interfaces", response_model=List[NetworkInterfaceOut])
async def list_network_interfaces(
    current_user: User = Depends(require_any_authenticated)
):
    """Module 1: List network capture interfaces on host."""
    return PcapCaptureService.get_available_interfaces()

# 2. Module 1: TCPDump Start Capture
@router.post("/captures/start", response_model=NetworkCaptureOut)
async def start_packet_capture(
    request: CaptureStartRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Module 1: Launch authorized TCPDump packet capture on specified interface."""
    capture = await PcapCaptureService.start_capture(
        db=db,
        interface=request.interface,
        duration_seconds=request.duration_seconds,
        capture_filter=request.capture_filter,
        max_packet_count=request.max_packet_count,
        max_file_size_mb=request.max_file_size_mb,
        output_filename=request.output_filename,
        capture_source=request.capture_source
    )
    
    await log_audit_event(
        db=db,
        action="TCPDUMP_CAPTURE_STARTED",
        resource="network_capture",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=capture.capture_id,
        details={"interface": request.interface, "duration": request.duration_seconds, "filter": request.capture_filter}
    )
    return capture

# 3. Module 1: TCPDump Stop Capture
@router.post("/captures/stop", response_model=NetworkCaptureOut)
async def stop_packet_capture(
    request: CaptureStopRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Module 1: Terminate active capture session and trigger automated analysis."""
    try:
        capture = await PcapCaptureService.stop_capture(db=db, capture_id=request.capture_id)
        await log_audit_event(
            db=db,
            action="TCPDUMP_CAPTURE_STOPPED",
            resource="network_capture",
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role,
            resource_id=capture.capture_id,
            details={"packets": capture.packet_count, "size_bytes": capture.file_size_bytes}
        )
        return capture
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

# 4. Module 2: PCAP Management - List Captures
@router.get("/captures", response_model=List[NetworkCaptureOut])
async def list_captures(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Module 2: Maintain metadata for each capture session."""
    stmt = select(NetworkCapture).order_by(NetworkCapture.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()

# 5. Module 2: Get Single Capture
@router.get("/captures/{capture_id}", response_model=NetworkCaptureOut)
async def get_capture(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(NetworkCapture).where(NetworkCapture.capture_id == capture_id)
    result = await db.execute(stmt)
    capture = result.scalars().first()
    if not capture:
        raise HTTPException(status_code=404, detail=f"Capture {capture_id} not found")
    return capture

# 6. Module 3: TShark Analysis - Inspect Parsed Packets
@router.get("/captures/{capture_id}/packets", response_model=List[PacketEventOut])
async def get_capture_packets(
    capture_id: str,
    limit: int = 100,
    offset: int = 0,
    protocol: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Module 3: Structured packet metadata extracted by TShark / Automated Parser."""
    stmt = select(NetworkPacketEvent).where(NetworkPacketEvent.capture_id == capture_id)
    if protocol:
        stmt = stmt.where(NetworkPacketEvent.protocol == protocol.upper())
    stmt = stmt.order_by(NetworkPacketEvent.frame_number.asc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

# 7. Module 4: Wireshark Investigation - Download Raw PCAP
@router.get("/captures/{capture_id}/download")
async def download_pcap(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Module 4: Download binary PCAP file for human investigation in Wireshark."""
    stmt = select(NetworkCapture).where(NetworkCapture.capture_id == capture_id)
    result = await db.execute(stmt)
    capture = result.scalars().first()
    if not capture:
        raise HTTPException(status_code=404, detail=f"Capture {capture_id} not found")

    file_path = Path(capture.file_path)
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="PCAP file does not exist on disk")

    return FileResponse(
        path=str(file_path),
        filename=capture.filename,
        media_type="application/vnd.tcpdump.pcap"
    )

# 8. Module 2 & 3: Upload PCAP for Automated Analysis
@router.post("/captures/upload", response_model=NetworkCaptureOut)
async def upload_pcap(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Allows analyst to upload external PCAP file to SENTINEL-X for automated analysis."""
    safe_filename = file.filename or f"uploaded_{int(datetime.now(timezone.utc).timestamp())}.pcap"
    if not safe_filename.endswith(".pcap") and not safe_filename.endswith(".pcapng"):
        safe_filename += ".pcap"

    dest_path = PCAP_STORAGE_DIR / safe_filename
    with open(dest_path, "wb") as buffer:
        content = await file.read()
        buffer.write(content)

    cap_id = f"CAP-UP{int(datetime.now(timezone.utc).timestamp()) % 1000:03d}"
    capture_record = NetworkCapture(
        capture_id=cap_id,
        filename=safe_filename,
        interface="Manual PCAP Upload",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=0,
        packet_count=0,
        file_size_bytes=len(content),
        capture_source="Manual Forensic Upload",
        status=CaptureStatus.COMPLETED.value,
        filter_applied=None,
        file_path=str(dest_path),
        metadata_json={"visibility_disclaimer": "Forensic offline file uploaded by analyst"}
    )
    db.add(capture_record)
    await db.commit()
    await db.refresh(capture_record)

    # Trigger TShark analysis
    await PcapCaptureService.analyze_capture(capture_record.capture_id)
    await db.refresh(capture_record)
    return capture_record

# 9. Module 3: Trigger Re-analysis
@router.post("/captures/{capture_id}/analyze", response_model=NetworkCaptureOut)
async def trigger_analysis(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Trigger TShark analysis and run correlation engine on an existing capture."""
    await PcapCaptureService.analyze_capture(capture_id)
    stmt = select(NetworkCapture).where(NetworkCapture.capture_id == capture_id)
    result = await db.execute(stmt)
    capture = result.scalars().first()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")
    return capture

# 10. Module 5: Network Traffic Dashboard Overview Stats
@router.get("/traffic", response_model=TrafficOverviewStats)
async def get_traffic_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Module 5: Real-time traffic metrics, protocols, and top communicating devices."""
    # Count packets
    total_pkts_res = await db.execute(select(func.count(NetworkPacketEvent.id)))
    total_pkts = total_pkts_res.scalar() or 0

    tcp_pkts_res = await db.execute(
        select(func.count(NetworkPacketEvent.id)).where(NetworkPacketEvent.protocol.in_(["TCP", "HTTP", "TLS", "RTSP", "SMB"]))
    )
    tcp_pkts = tcp_pkts_res.scalar() or 0

    udp_pkts_res = await db.execute(
        select(func.count(NetworkPacketEvent.id)).where(NetworkPacketEvent.protocol.in_(["UDP", "DNS", "NTP"]))
    )
    udp_pkts = udp_pkts_res.scalar() or 0

    icmp_pkts_res = await db.execute(
        select(func.count(NetworkPacketEvent.id)).where(NetworkPacketEvent.protocol == "ICMP")
    )
    icmp_pkts = icmp_pkts_res.scalar() or 0

    other_pkts = max(0, total_pkts - (tcp_pkts + udp_pkts + icmp_pkts))

    # Unique endpoints
    src_res = await db.execute(select(NetworkPacketEvent.source_ip).distinct())
    src_ips = set(r[0] for r in src_res.fetchall())
    dst_res = await db.execute(select(NetworkPacketEvent.destination_ip).distinct())
    dst_ips = set(r[0] for r in dst_res.fetchall())
    all_devices = src_ips.union(dst_ips)

    # Top communicating devices
    conns_res = await db.execute(select(NetworkConnection))
    all_conns = conns_res.scalars().all()

    device_stats: Dict[str, Dict[str, Any]] = {}
    for c in all_conns:
        # Tally source
        s = device_stats.setdefault(c.source_ip, {"packets": 0, "bytes": 0, "conns": 0})
        s["packets"] += c.packet_count
        s["bytes"] += c.byte_count
        s["conns"] += 1

        # Tally dest
        d = device_stats.setdefault(c.destination_ip, {"packets": 0, "bytes": 0, "conns": 0})
        d["packets"] += c.packet_count
        d["bytes"] += c.byte_count
        d["conns"] += 1

    # Map to Phase 1 Assets
    assets_res = await db.execute(select(Asset))
    asset_map = {a.ip_address: a for a in assets_res.scalars().all()}

    top_devices_list = []
    sorted_devs = sorted(device_stats.items(), key=lambda x: x[1]["packets"], reverse=True)[:10]
    for ip, s in sorted_devs:
        ast = asset_map.get(ip)
        top_devices_list.append(TopDeviceStats(
            device_ip=ip,
            hostname=ast.hostname if ast else None,
            device_type=ast.device_type if ast else ("External Public Node" if not ip.startswith("192.168.") else "Internal Host"),
            packet_count=s["packets"],
            byte_count=s["bytes"],
            connections=s["conns"],
            role="Discovered Asset" if ast else "Host"
        ))

    # Protocol distribution
    proto_stmt = select(NetworkPacketEvent.protocol, func.count(NetworkPacketEvent.id)).group_by(NetworkPacketEvent.protocol)
    proto_res = await db.execute(proto_stmt)
    proto_dist = {r[0]: r[1] for r in proto_res.fetchall()}

    return TrafficOverviewStats(
        total_packets=total_pkts,
        tcp_packets=tcp_pkts,
        udp_packets=udp_pkts,
        icmp_packets=icmp_pkts,
        other_packets=other_pkts,
        unique_devices=len(all_devices),
        unique_destinations=len(dst_ips),
        top_communicating_devices=top_devices_list,
        protocol_distribution=proto_dist,
        visibility_disclaimer=VISIBILITY_DISCLAIMER
    )

# 11. Module 5: Network Connections Flows
@router.get("/connections", response_model=List[NetworkConnectionOut])
async def list_connections(
    capture_id: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(NetworkConnection)
    if capture_id:
        stmt = stmt.where(NetworkConnection.capture_id == capture_id)
    stmt = stmt.order_by(NetworkConnection.packet_count.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

# 12. Module 6 & 7: Device & OS/Software/Firmware Correlation View
@router.get("/correlations")
async def get_correlations(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Module 6 & 7: Correlates Phase 1 Assets + OS/Firmware + CVEs with Phase 2 Traffic."""
    return await get_device_correlations(db)

# 13. Module 8, 9, 10, 11: Security Findings & Indicators
@router.get("/alerts", response_model=List[CorrelatedFindingOut])
async def list_correlated_findings(
    severity: Optional[str] = None,
    category: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    """Lists Correlated Security Findings, Behavior Indicators, and Threat Indicators."""
    stmt = select(CorrelatedFinding)
    if severity:
        stmt = stmt.where(CorrelatedFinding.severity == severity.upper())
    if category:
        stmt = stmt.where(CorrelatedFinding.category == category)
    if status:
        stmt = stmt.where(CorrelatedFinding.status == status.upper())
    stmt = stmt.order_by(CorrelatedFinding.created_at.desc())
    result = await db.execute(stmt)
    findings = result.scalars().all()

    # Populate asset attributes
    assets_res = await db.execute(select(Asset))
    assets_by_id = {a.id: a for a in assets_res.scalars().all()}

    output = []
    for f in findings:
        item = CorrelatedFindingOut.model_validate(f)
        if f.affected_asset_id and f.affected_asset_id in assets_by_id:
            ast = assets_by_id[f.affected_asset_id]
            item.asset_hostname = ast.hostname
            item.asset_device_type = ast.device_type
            item.asset_vendor = ast.vendor
            item.asset_os = f"{ast.os_name or ''} {ast.os_version or ''}".strip()
            item.asset_firmware = ast.firmware_version
        output.append(item)
    return output

# 14. Module 12: Analyst Workflow - Triage Finding
@router.post("/alerts/{finding_id}/investigate", response_model=CorrelatedFindingOut)
async def update_analyst_investigation(
    finding_id: int,
    req: AnalystInvestigationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    """Module 12: Analyst records investigation notes, conclusion, and updates incident state."""
    stmt = select(CorrelatedFinding).where(CorrelatedFinding.id == finding_id)
    result = await db.execute(stmt)
    finding = result.scalars().first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = req.status.upper()
    if req.analyst_conclusion:
        finding.analyst_conclusion = req.analyst_conclusion
    if req.analyst_notes:
        finding.analyst_notes = req.analyst_notes
    finding.assigned_to = req.assigned_to or current_user.full_name
    if finding.status in ["RESOLVED", "FALSE_POSITIVE", "BENIGN_ANOMALY"]:
        finding.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(finding)

    await log_audit_event(
        db=db,
        action="ANALYST_FINDING_TRIAGED",
        resource="correlated_finding",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=finding.alert_code,
        details={"status": finding.status, "conclusion": finding.analyst_conclusion}
    )

    item = CorrelatedFindingOut.model_validate(finding)
    if finding.affected_asset_id:
        ast_res = await db.execute(select(Asset).where(Asset.id == finding.affected_asset_id))
        ast = ast_res.scalars().first()
        if ast:
            item.asset_hostname = ast.hostname
            item.asset_device_type = ast.device_type
            item.asset_vendor = ast.vendor
            item.asset_os = f"{ast.os_name or ''} {ast.os_version or ''}".strip()
            item.asset_firmware = ast.firmware_version
    return item
