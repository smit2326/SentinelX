from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Dict, Any
from app.models.audit_log import AuditLog
from app.core.logger import logger

async def log_audit_event(
    db: AsyncSession,
    action: str,
    resource: str,
    actor_email: str = "system",
    actor_role: str = "system",
    actor_id: Optional[int] = None,
    resource_id: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: str = "127.0.0.1",
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    try:
        audit_entry = AuditLog(
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            action=action,
            resource=resource,
            resource_id=str(resource_id) if resource_id else None,
            status=status,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details or {}
        )
        db.add(audit_entry)
        await db.commit()
        await db.refresh(audit_entry)
        logger.info(f"AUDIT LOG: [{actor_email}] performed {action} on {resource}:{resource_id} -> {status}")
        return audit_entry
    except Exception as e:
        logger.error(f"Failed to record audit log: {e}")
        await db.rollback()
        raise e
