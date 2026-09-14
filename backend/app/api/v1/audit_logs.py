from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import List, Optional
from app.core.database import get_db
from app.models.user import User, UserRole
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogOut
from app.services.auth_service import require_roles

router = APIRouter(prefix="/audit-logs", tags=["Compliance & Audit Logs"])

@router.get("", response_model=List[AuditLogOut])
async def list_audit_logs(
    action: Optional[str] = None,
    resource: Optional[str] = None,
    actor_email: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN.value, UserRole.AUDITOR.value, UserRole.ANALYST.value]))
):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if resource:
        stmt = stmt.where(AuditLog.resource == resource)
    if actor_email:
        stmt = stmt.where(AuditLog.actor_email.ilike(f"%{actor_email}%"))
    if search:
        search_filter = f"%{search}%"
        stmt = stmt.where(
            or_(
                AuditLog.action.ilike(search_filter),
                AuditLog.resource.ilike(search_filter),
                AuditLog.actor_email.ilike(search_filter),
                AuditLog.ip_address.ilike(search_filter)
            )
        )
    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()
