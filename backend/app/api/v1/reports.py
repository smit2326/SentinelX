from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.models.user import User
from app.schemas.report import ExecutiveReport
from app.services.auth_service import require_any_authenticated
from app.services.report_service import generate_executive_security_report
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/reports", tags=["Executive Security Reporting"])

@router.get("/executive", response_model=ExecutiveReport)
async def get_executive_report(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    report_data = await generate_executive_security_report(db)
    
    await log_audit_event(
        db=db,
        action="EXECUTIVE_REPORT_GENERATED",
        resource="reports",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        details={"risk_score": report_data["overall_risk_score"]}
    )
    
    return report_data
