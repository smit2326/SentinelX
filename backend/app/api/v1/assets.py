from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List, Optional
from datetime import datetime, timezone
from app.core.database import get_db, AsyncSessionLocal
from app.models.user import User
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.alert import Alert
from app.schemas.asset import AssetOut, AssetCreate, AssetUpdate, ScanRequest
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin, require_admin
from app.services.scanner_service import execute_network_discovery
from app.services.nmap_service import get_nmap_info, execute_laptop_nmap_vuln_audit, get_local_machine_details
from app.services.risk_engine import calculate_asset_risk
from app.services.audit_service import log_audit_event
from app.services.websocket_manager import ws_manager

router = APIRouter(prefix="/assets", tags=["Asset Discovery & Inventory"])

@router.get("/nmap/status")
async def check_nmap_status(
    current_user: User = Depends(require_any_authenticated)
):
    nmap_info = get_nmap_info()
    host_details = get_local_machine_details()
    return {
        **nmap_info,
        "host": host_details
    }

@router.post("/scan/laptop")
async def trigger_laptop_nmap_scan(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst_or_admin),
    target_ip: Optional[str] = "127.0.0.1"
):
    async def _run():
        async with AsyncSessionLocal() as session:
            try:
                await execute_laptop_nmap_vuln_audit(session, target_ip or "127.0.0.1", current_user.email)
            except Exception as e:
                print(f"Error in laptop nmap audit task: {e}")

    background_tasks.add_task(_run)
    return {
        "status": "NMAP_LAPTOP_SCAN_DISPATCHED",
        "target": target_ip or "127.0.0.1",
        "dispatched_by": current_user.email,
        "message": "Local laptop Nmap vulnerability scan dispatched. Real-time progress streaming over WebSocket."
    }

@router.get("", response_model=List[AssetOut])
async def list_assets(
    device_type: Optional[str] = None,
    is_cctv: Optional[bool] = None,
    is_iot: Optional[bool] = None,
    is_quarantined: Optional[bool] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Asset)
    if device_type:
        stmt = stmt.where(Asset.device_type == device_type)
    if is_cctv is not None:
        stmt = stmt.where(Asset.is_cctv == is_cctv)
    if is_iot is not None:
        stmt = stmt.where(Asset.is_iot == is_iot)
    if is_quarantined is not None:
        stmt = stmt.where(Asset.is_quarantined == is_quarantined)
    if search:
        search_filter = f"%{search}%"
        stmt = stmt.where(
            or_(
                Asset.ip_address.ilike(search_filter),
                Asset.hostname.ilike(search_filter),
                Asset.vendor.ilike(search_filter),
                Asset.os_name.ilike(search_filter)
            )
        )
    stmt = stmt.order_by(Asset.risk_score.desc())
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/{asset_id}")
async def get_asset_details(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Asset).where(Asset.id == asset_id)
    asset = (await db.execute(stmt)).scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Fetch related vulns and alerts
    vulns_res = await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset_id))
    vulns = vulns_res.scalars().all()
    
    alerts_res = await db.execute(select(Alert).where(Alert.affected_asset_id == asset_id).order_by(Alert.created_at.desc()))
    alerts = alerts_res.scalars().all()
    
    return {
        "asset": asset,
        "vulnerabilities": vulns,
        "alerts": alerts
    }

@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(
    asset_in: AssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    stmt = select(Asset).where(Asset.ip_address == asset_in.ip_address)
    existing = (await db.execute(stmt)).scalars().first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset with this IP already exists")
    
    new_asset = Asset(**asset_in.dict())
    new_asset.last_scanned = datetime.now(timezone.utc)
    new_asset.risk_score = calculate_asset_risk(new_asset, [], [])
    
    db.add(new_asset)
    await db.commit()
    await db.refresh(new_asset)
    
    await log_audit_event(
        db=db,
        action="ASSET_CREATED",
        resource="assets",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(new_asset.id),
        details={"ip": new_asset.ip_address, "device_type": new_asset.device_type}
    )
    return new_asset

@router.put("/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: int,
    asset_in: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    stmt = select(Asset).where(Asset.id == asset_id)
    asset = (await db.execute(stmt)).scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    for field, val in asset_in.dict(exclude_unset=True).items():
        setattr(asset, field, val)
        
    await db.commit()
    await db.refresh(asset)
    
    await log_audit_event(
        db=db,
        action="ASSET_UPDATED",
        resource="assets",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(asset.id),
        details={"ip": asset.ip_address}
    )
    return asset

@router.post("/{asset_id}/quarantine")
async def toggle_quarantine_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    stmt = select(Asset).where(Asset.id == asset_id)
    asset = (await db.execute(stmt)).scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    asset.is_quarantined = not asset.is_quarantined
    asset.status = "Quarantined" if asset.is_quarantined else "Online"
    
    # Recalculate risk score
    vulns_res = await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset.id))
    vulns = vulns_res.scalars().all()
    alerts_res = await db.execute(select(Alert).where(Alert.affected_asset_id == asset.id))
    alerts = alerts_res.scalars().all()
    asset.risk_score = calculate_asset_risk(asset, vulns, alerts)
    
    await db.commit()
    await db.refresh(asset)
    
    action_name = "ASSET_QUARANTINED" if asset.is_quarantined else "ASSET_UNQUARANTINED"
    await log_audit_event(
        db=db,
        action=action_name,
        resource="assets",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(asset.id),
        details={"ip": asset.ip_address, "is_quarantined": asset.is_quarantined}
    )
    
    await ws_manager.broadcast_asset_update({
        "id": asset.id,
        "ip_address": asset.ip_address,
        "status": asset.status,
        "is_quarantined": asset.is_quarantined,
        "risk_score": asset.risk_score
    })
    
    return {
        "message": f"Asset {asset.ip_address} quarantine status updated to {asset.is_quarantined}",
        "asset": asset
    }

async def run_async_scan(target_subnet: str, scan_type: str, actor_email: str):
    async with AsyncSessionLocal() as db_session:
        try:
            if scan_type in ["nmap_vuln", "laptop_vuln"]:
                target = target_subnet.split("/")[0] if "/" in target_subnet else target_subnet
                await execute_laptop_nmap_vuln_audit(db_session, target or "127.0.0.1", actor_email)
            else:
                await execute_network_discovery(db_session, target_subnet, scan_type, actor_email)
        except Exception as e:
            print(f"Error in async scan task: {e}")

@router.post("/scan")
async def trigger_scan(
    scan_req: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst_or_admin),
    db: AsyncSession = Depends(get_db)
):
    background_tasks.add_task(
        run_async_scan,
        scan_req.target_subnet,
        scan_req.scan_type,
        current_user.email
    )
    return {
        "status": "SCAN_DISPATCHED",
        "target_subnet": scan_req.target_subnet,
        "scan_type": scan_req.scan_type,
        "dispatched_by": current_user.email,
        "message": "Discovery scan is executing in the background. Real-time updates streaming over WebSocket."
    }

@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    stmt = select(Asset).where(Asset.id == asset_id)
    asset = (await db.execute(stmt)).scalars().first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    await db.delete(asset)
    await db.commit()
    
    await log_audit_event(
        db=db,
        action="ASSET_DELETED",
        resource="assets",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(asset_id),
        details={"deleted_ip": asset.ip_address}
    )
    return {"message": f"Asset {asset.ip_address} deleted successfully"}
