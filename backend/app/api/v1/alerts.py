import random
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from typing import List, Optional
from datetime import datetime, timezone
from app.core.database import get_db
from app.models.user import User
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.schemas.alert import AlertOut, AlertCreate, AlertUpdate, AlertStats
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.audit_service import log_audit_event
from app.services.websocket_manager import ws_manager
from app.services.risk_engine import calculate_asset_risk

router = APIRouter(prefix="/alerts", tags=["Incidents & Traffic Monitoring Alerts"])

@router.get("", response_model=List[AlertOut])
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    if status:
        stmt = stmt.where(Alert.status == status.upper())
    if category:
        stmt = stmt.where(Alert.category == category)
    if search:
        search_filter = f"%{search}%"
        stmt = stmt.where(
            or_(
                Alert.title.ilike(search_filter),
                Alert.description.ilike(search_filter),
                Alert.source_ip.ilike(search_filter),
                Alert.destination_ip.ilike(search_filter)
            )
        )
    stmt = stmt.order_by(Alert.created_at.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/stats", response_model=AlertStats)
async def get_alert_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Alert)
    res = await db.execute(stmt)
    alerts = res.scalars().all()
    
    total_active = sum(1 for a in alerts if a.status == "ACTIVE")
    critical_active = sum(1 for a in alerts if a.status == "ACTIVE" and a.severity == "CRITICAL")
    high_active = sum(1 for a in alerts if a.status == "ACTIVE" and a.severity == "HIGH")
    investigating = sum(1 for a in alerts if a.status == "INVESTIGATING")
    resolved_today = sum(1 for a in alerts if a.status == "RESOLVED")
    
    return {
        "total_active": total_active,
        "critical_active": critical_active,
        "high_active": high_active,
        "investigating": investigating,
        "resolved_today": resolved_today
    }

@router.put("/{alert_id}/status", response_model=AlertOut)
async def update_alert_status(
    alert_id: int,
    alert_update: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    stmt = select(Alert).where(Alert.id == alert_id)
    alert = (await db.execute(stmt)).scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    prev_status = alert.status
    if alert_update.status:
        alert.status = alert_update.status.upper()
        if alert.status in ["RESOLVED", "DISMISSED"]:
            alert.resolved_at = datetime.now(timezone.utc)
    if alert_update.assigned_to:
        alert.assigned_to = alert_update.assigned_to
        
    await db.commit()
    await db.refresh(alert)
    
    # Recalculate asset risk if linked
    if alert.affected_asset_id:
        asset_res = await db.execute(select(Asset).where(Asset.id == alert.affected_asset_id))
        asset = asset_res.scalars().first()
        if asset:
            vulns = (await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset.id))).scalars().all()
            all_alerts = (await db.execute(select(Alert).where(Alert.affected_asset_id == asset.id))).scalars().all()
            asset.risk_score = calculate_asset_risk(asset, vulns, all_alerts)
            await db.commit()
    
    await log_audit_event(
        db=db,
        action="ALERT_STATUS_UPDATED",
        resource="alerts",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(alert.id),
        details={"title": alert.title, "prev_status": prev_status, "new_status": alert.status}
    )
    return alert

SIMULATED_ATTACK_PATTERNS = [
    {
        "title": "CCTV Unauthenticated RTSP Feed Stream Hijack Attempt",
        "category": "CCTV / IoT Security",
        "severity": "CRITICAL",
        "protocol": "RTSP",
        "desc": "An unauthorized external IP attempted to negotiate raw RTSP media session on port 554 without basic auth headers.",
        "hex": "53 45 54 55 50 20 72 74 73 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 31 2e 34 35 2f 6c 69 76 65 2e 73 64 70"
    },
    {
        "title": "TCP SYN Flood Anomaly Detected",
        "category": "Traffic Monitoring",
        "severity": "HIGH",
        "protocol": "TCP",
        "desc": "Exceeded 8,500 SYN packets/sec towards internal Web Application Gateway with spoofed sources.",
        "hex": "45 00 00 3c 1a 2b 40 00 40 06 b2 a1 c0 a8 01 69 c0 a8 01 0a 00 50"
    },
    {
        "title": "Active Directory Kerberoasting Ticket Request Spike",
        "category": "Lateral Movement",
        "severity": "CRITICAL",
        "protocol": "Kerberos",
        "desc": "High volume of TGS-REQ packets with RC4 encryption requested for service principal names (SPNs).",
        "hex": "6a 81 b5 30 81 b2 a0 03 02 01 05 a1 03 02 01 0c a2 07 03 05 00 20"
    },
    {
        "title": "IoT Modbus Protocol Register Overwrite Attempt",
        "category": "Industrial IoT Anomaly",
        "severity": "HIGH",
        "protocol": "MODBUS-TCP",
        "desc": "Function Code 16 (Write Multiple Holding Registers) detected from unlisted management IP.",
        "hex": "00 01 00 00 00 09 01 10 00 01 00 01 02 00 64"
    }
]

@router.post("/simulate", response_model=AlertOut)
async def simulate_threat_alert(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    pattern = random.choice(SIMULATED_ATTACK_PATTERNS)
    assets = (await db.execute(select(Asset))).scalars().all()
    target_asset = random.choice(assets) if assets else None
    
    src_ip = f"{random.randint(45, 198)}.{random.randint(10, 240)}.{random.randint(1, 250)}.{random.randint(2, 254)}"
    
    alert = Alert(
        title=pattern["title"],
        category=pattern["category"],
        severity=pattern["severity"],
        source_ip=src_ip,
        destination_ip=target_asset.ip_address if target_asset else "192.168.1.10",
        protocol=pattern["protocol"],
        affected_asset_id=target_asset.id if target_asset else None,
        description=pattern["desc"],
        raw_packet_hex=pattern["hex"],
        metadata_json={"simulated": True, "triggered_by": current_user.email},
        status="ACTIVE"
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    
    # Broadcast live over WebSocket
    await ws_manager.broadcast_alert({
        "id": alert.id,
        "title": alert.title,
        "category": alert.category,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "protocol": alert.protocol,
        "description": alert.description,
        "raw_packet_hex": alert.raw_packet_hex,
        "status": alert.status,
        "created_at": alert.created_at.isoformat()
    })
    
    await log_audit_event(
        db=db,
        action="SIMULATED_ALERT_TRIGGERED",
        resource="alerts",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(alert.id),
        details={"title": alert.title, "severity": alert.severity}
    )
    
    return alert
