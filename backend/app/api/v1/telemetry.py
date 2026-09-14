import asyncio
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone
from app.core.database import get_db, AsyncSessionLocal
from app.models.user import User
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.alert import Alert
from app.services.auth_service import require_any_authenticated
from app.services.risk_engine import calculate_global_network_risk
from app.services.websocket_manager import ws_manager

router = APIRouter(tags=["Telemetry & WebSocket Stream"])

@router.get("/telemetry/dashboard")
async def get_dashboard_telemetry(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    # Global risk
    risk_info = await calculate_global_network_risk(db)
    
    # Asset stats
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()
    
    total_assets = len(assets)
    online_assets = sum(1 for a in assets if a.status == "Online")
    quarantined_assets = sum(1 for a in assets if a.is_quarantined)
    cctv_iot_count = sum(1 for a in assets if (a.is_cctv or a.is_iot))
    
    # Vulns stats
    vulns_res = await db.execute(select(Vulnerability))
    vulns = vulns_res.scalars().all()
    
    vuln_breakdown = {
        "critical": sum(1 for v in vulns if v.severity == "CRITICAL" and v.status in ["OPEN", "INVESTIGATING"]),
        "high": sum(1 for v in vulns if v.severity == "HIGH" and v.status in ["OPEN", "INVESTIGATING"]),
        "medium": sum(1 for v in vulns if v.severity == "MEDIUM" and v.status in ["OPEN", "INVESTIGATING"]),
        "low": sum(1 for v in vulns if v.severity == "LOW" and v.status in ["OPEN", "INVESTIGATING"]),
        "mitigated": sum(1 for v in vulns if v.status == "MITIGATED")
    }
    
    # Active alerts
    alerts_res = await db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(8))
    recent_alerts = alerts_res.scalars().all()
    
    active_alerts_count = sum(1 for a in recent_alerts if a.status == "ACTIVE")
    
    # Device type distribution
    device_distribution = {}
    for a in assets:
        dtype = a.device_type or "Unknown"
        device_distribution[dtype] = device_distribution.get(dtype, 0) + 1
        
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_summary": risk_info,
        "assets_summary": {
            "total": total_assets,
            "online": online_assets,
            "quarantined": quarantined_assets,
            "cctv_iot": cctv_iot_count,
            "distribution": device_distribution
        },
        "vulnerabilities_summary": vuln_breakdown,
        "recent_alerts": recent_alerts,
        "active_alerts_count": active_alerts_count
    }

@router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Listen for client heartbeat/ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        ws_manager.disconnect(websocket)
