import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from app.core.database import get_db
from app.models.user import User
from app.models.system_config import SystemConfig
from app.schemas.system_config import SystemConfigOut, SystemConfigUpdate
from app.services.auth_service import require_admin, require_any_authenticated
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/config", tags=["System Configuration & Integrations"])

@router.get("", response_model=List[SystemConfigOut])
async def get_all_configs(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(SystemConfig).order_by(SystemConfig.category.asc(), SystemConfig.key.asc())
    result = await db.execute(stmt)
    configs = result.scalars().all()
    
    # Mask secrets if not admin
    if current_user.role != "admin":
        for c in configs:
            if c.is_secret:
                c.value = "********"
    return configs

@router.put("/{key}", response_model=SystemConfigOut)
async def update_config(
    key: str,
    config_in: SystemConfigUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    stmt = select(SystemConfig).where(SystemConfig.key == key)
    config = (await db.execute(stmt)).scalars().first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuration key not found")
    
    config.value = config_in.value
    if config_in.description:
        config.description = config_in.description
        
    await db.commit()
    await db.refresh(config)
    
    await log_audit_event(
        db=db,
        action="CONFIG_UPDATED",
        resource="system_config",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=key,
        details={"key": key, "new_value": "********" if config.is_secret else config.value}
    )
    return config

@router.post("/test-webhook")
async def test_webhook(
    webhook_url: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    try:
        payload = {
            "source": "SENTINEL-X SIEM Dispatcher",
            "event": "WEBHOOK_VERIFICATION_TEST",
            "actor": current_user.email
        }
        status_msg = "Webhook test payload formatted successfully"
        if webhook_url.startswith("http://") or webhook_url.startswith("https://"):
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.post(webhook_url, json=payload)
                    status_msg = f"Dispatched HTTP POST to {webhook_url} (Response: {resp.status_code})"
            except Exception as net_err:
                status_msg = f"Endpoint unreachable: {str(net_err)}"

        return {
            "status": "SUCCESS",
            "message": status_msg,
            "delivered_payload": payload
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to dispatch webhook: {str(e)}")
