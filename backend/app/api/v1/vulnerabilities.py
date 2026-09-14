from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from typing import List, Optional
from datetime import datetime, timezone
from app.core.database import get_db
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnSeverity, VulnStatus
from app.models.asset import Asset
from app.schemas.vulnerability import VulnerabilityOut, VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityStats
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.audit_service import log_audit_event
from app.services.risk_engine import calculate_asset_risk

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Assessment & CVE Triage"])

@router.get("", response_model=List[VulnerabilityOut])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[int] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Vulnerability)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity.upper())
    if status:
        stmt = stmt.where(Vulnerability.status == status.upper())
    if asset_id:
        stmt = stmt.where(Vulnerability.affected_asset_id == asset_id)
    if search:
        search_filter = f"%{search}%"
        stmt = stmt.where(
            or_(
                Vulnerability.cve_id.ilike(search_filter),
                Vulnerability.title.ilike(search_filter),
                Vulnerability.description.ilike(search_filter),
                Vulnerability.affected_service.ilike(search_filter)
            )
        )
    stmt = stmt.order_by(Vulnerability.cvss_score.desc())
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/stats", response_model=VulnerabilityStats)
async def get_vulnerability_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Vulnerability)
    res = await db.execute(stmt)
    vulns = res.scalars().all()
    
    total = len(vulns)
    critical = sum(1 for v in vulns if v.severity == "CRITICAL" and v.status in ["OPEN", "INVESTIGATING"])
    high = sum(1 for v in vulns if v.severity == "HIGH" and v.status in ["OPEN", "INVESTIGATING"])
    medium = sum(1 for v in vulns if v.severity == "MEDIUM" and v.status in ["OPEN", "INVESTIGATING"])
    low = sum(1 for v in vulns if v.severity == "LOW" and v.status in ["OPEN", "INVESTIGATING"])
    mitigated = sum(1 for v in vulns if v.status == "MITIGATED")
    
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "mitigated": mitigated
    }

@router.get("/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated)
):
    stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
    vuln = (await db.execute(stmt)).scalars().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln

@router.put("/{vuln_id}/triage", response_model=VulnerabilityOut)
async def triage_vulnerability(
    vuln_id: int,
    vuln_update: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst_or_admin)
):
    stmt = select(Vulnerability).where(Vulnerability.id == vuln_id)
    vuln = (await db.execute(stmt)).scalars().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    prev_status = vuln.status
    if vuln_update.status:
        vuln.status = vuln_update.status.upper()
        if vuln.status == "MITIGATED":
            vuln.resolved_at = datetime.now(timezone.utc)
    if vuln_update.remediation is not None:
        vuln.remediation = vuln_update.remediation
        
    await db.commit()
    await db.refresh(vuln)
    
    # Recalculate asset risk score if linked to an asset
    if vuln.affected_asset_id:
        asset_res = await db.execute(select(Asset).where(Asset.id == vuln.affected_asset_id))
        asset = asset_res.scalars().first()
        if asset:
            all_vulns = (await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset.id))).scalars().all()
            from app.models.alert import Alert
            all_alerts = (await db.execute(select(Alert).where(Alert.affected_asset_id == asset.id))).scalars().all()
            asset.risk_score = calculate_asset_risk(asset, all_vulns, all_alerts)
            await db.commit()
            
    await log_audit_event(
        db=db,
        action="VULNERABILITY_TRIAGED",
        resource="vulnerabilities",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role,
        resource_id=str(vuln.id),
        details={
            "cve_id": vuln.cve_id,
            "previous_status": prev_status,
            "new_status": vuln.status
        }
    )
    return vuln
