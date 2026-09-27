"""
Phase 3 Security Analytics API Router for SENTINEL-X.
Exposes evidence-oriented risk assessments, behavioral signals,
and versioned feature sets without exposing unnecessary mathematical internals.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.user import User
from app.models.asset import Asset
from app.models.analytics import RiskAssessment, FeatureSet, BehavioralBaseline
from app.schemas.analytics import (
    RiskOverviewOut,
    RiskAssessmentOut,
    BehavioralSignalOut,
    FeatureSetOut
)
from app.services.auth_service import require_any_authenticated
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.feature_engineering import FeatureEngineeringService
from app.services.baseline_engine import BaselineEngine

router = APIRouter(prefix="/analytics", tags=["Phase 3 — Security Analytics"])


@router.get("/risk", response_model=RiskOverviewOut)
async def get_risk_overview(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns platform-wide risk distribution across all active assets,
    categorized into Low, Moderate, High, and Critical bands.
    """
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()

    counts = {"Critical": 0, "High": 0, "Moderate": 0, "Low": 0}
    recent_changes = []

    for a in assets:
        lvl = RiskScoringEngine.classify_risk_level(a.risk_score or 0.0)
        counts[lvl] = counts.get(lvl, 0) + 1

        # Check latest risk assessment explanation
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.asset_id == a.id)
            .order_by(RiskAssessment.timestamp.desc())
        )
        assess_res = await db.execute(stmt)
        latest = assess_res.scalars().first()

        reason = "Baseline posture assessed"
        if latest and latest.explanation_list:
            reason = "; ".join(latest.explanation_list[:2])

        recent_changes.append({
            "asset_id": a.id,
            "hostname": a.hostname or a.ip_address,
            "ip_address": a.ip_address,
            "risk_score": a.risk_score or 0.0,
            "risk_level": lvl,
            "status": a.status,
            "reason": reason
        })

    return RiskOverviewOut(
        total_assets_assessed=len(assets),
        distribution=counts,
        recent_changes=recent_changes,
        methodology_version=RiskScoringEngine.METHODOLOGY_VERSION
    )


@router.get("/assets/{asset_id}", response_model=RiskAssessmentOut)
async def get_asset_risk_assessment(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Provides the detailed, explainable risk assessment for a specific asset.
    Computes or retrieves the component breakdown and audit evidence.
    """
    asset_res = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_res.scalars().first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Fetch latest or calculate fresh deterministic risk
    stmt = (
        select(RiskAssessment)
        .where(RiskAssessment.asset_id == asset_id)
        .order_by(RiskAssessment.timestamp.desc())
    )
    res = await db.execute(stmt)
    latest = res.scalars().first()

    if not latest:
        latest = await RiskScoringEngine.assess_asset_risk(db, asset_id)

    return latest


@router.get("/network", response_model=List[BehavioralSignalOut])
async def get_behavioral_signals(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns empirical behavioral signals derived from network flows and baseline comparisons.
    Uses non-alarmist terminology ('Deviation detected' vs 'Attack confirmed').
    """
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()
    signals: List[BehavioralSignalOut] = []

    for a in assets:
        # Check baseline status
        base_res = await db.execute(select(BehavioralBaseline).where(BehavioralBaseline.asset_id == a.id))
        baseline = base_res.scalars().first()

        # Generate feature set
        fs = await FeatureEngineeringService.generate_feature_set(db, a.id)
        net_feat = fs.network_features or {}
        dev_eval = BaselineEngine.evaluate_traffic_deviation(net_feat, baseline)

        rec_action = (
            "Review associated PCAP evidence and connection rate history."
            if dev_eval["is_anomalous"] else
            "Maintain passive monitoring."
        )

        signals.append(BehavioralSignalOut(
            asset_id=a.id,
            hostname=a.hostname or a.ip_address,
            ip_address=a.ip_address,
            signal=dev_eval["status"],
            evidence=dev_eval["explanation"],
            deviation_ratio=dev_eval["deviation_ratio"],
            recommended_action=rec_action
        ))

    return signals


@router.get("/features/assets/{asset_id}", response_model=FeatureSetOut)
async def get_asset_feature_set(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns the versioned security feature set extracted for an asset.
    """
    stmt = (
        select(FeatureSet)
        .where(FeatureSet.asset_id == asset_id)
        .order_by(FeatureSet.timestamp.desc())
    )
    res = await db.execute(stmt)
    fs = res.scalars().first()

    if not fs:
        fs = await FeatureEngineeringService.generate_feature_set(db, asset_id)

    return fs
