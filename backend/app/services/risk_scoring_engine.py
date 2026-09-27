"""
Phase 3 Deterministic & Explainable Risk Scoring Engine for SENTINEL-X.
Implements the versioned methodology:
Risk Score = Vulnerability Risk (40%) + Exposure Risk (25%) + Asset Criticality (20%) + Behavioral Risk (15%).
Generates evidence-grounded explanations without arbitrary or synthetic numbers.
Methodology Version: v1.0
"""

from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.analytics import FeatureSet, BehavioralBaseline, RiskAssessment
from app.services.feature_engineering import FeatureEngineeringService


class RiskScoringEngine:
    """
    Computes deterministic, auditable security risk assessments.
    Deconstructs the final score into 4 explainable components and returns itemized evidence.
    """

    METHODOLOGY_VERSION = "v1.0"

    WEIGHT_VULNERABILITY_MAX = 40.0
    WEIGHT_EXPOSURE_MAX = 25.0
    WEIGHT_CRITICALITY_MAX = 20.0
    WEIGHT_BEHAVIORAL_MAX = 15.0

    CRITICALITY_POINTS = {
        "Low": 5.0,
        "Medium": 10.0,
        "High": 15.0,
        "Critical": 20.0
    }

    @classmethod
    def classify_risk_level(cls, score: float) -> str:
        """Categorizes raw 0-100 score into standard documented risk bands."""
        if score >= 75.0:
            return "Critical"
        if score >= 50.0:
            return "High"
        if score >= 25.0:
            return "Moderate"
        return "Low"

    @classmethod
    def calculate_vulnerability_component(
        cls,
        vuln_features: Dict[str, Any]
    ) -> (float, List[str]):
        """Calculates vulnerability component (Max 40.0) and generates explanations."""
        crit_cve = vuln_features.get("critical_cve_count", 0)
        high_cve = vuln_features.get("high_cve_count", 0)
        med_cve = vuln_features.get("medium_cve_count", 0)
        low_cve = vuln_features.get("low_cve_count", 0)
        exploitable = vuln_features.get("exploitable_vulnerability_count", 0)
        unpatched = vuln_features.get("unpatched_vulnerability_count", 0)

        score = (crit_cve * 15.0) + (high_cve * 8.0) + (med_cve * 3.0) + (low_cve * 1.0)
        if exploitable > 0:
            score += 5.0

        clamped = min(score, cls.WEIGHT_VULNERABILITY_MAX)

        explanations = []
        if crit_cve > 0:
            explanations.append(f"{crit_cve} Critical-severity CVE finding(s) detected")
        if high_cve > 0:
            explanations.append(f"{high_cve} High-severity CVE finding(s) detected")
        if unpatched > 0:
            explanations.append(f"{unpatched} missing security patch(es) pending installation")
        if exploitable > 0:
            explanations.append(f"{exploitable} vulnerability(ies) have known active public exploits")

        return round(clamped, 1), explanations

    @classmethod
    def calculate_exposure_component(
        cls,
        exposure_features: Dict[str, Any]
    ) -> (float, List[str]):
        """Calculates exposure component (Max 25.0) and generates explanations."""
        is_ext = exposure_features.get("internet_exposed", 0)
        priv_ports = exposure_features.get("privileged_service_count", 0)
        sens_ports = exposure_features.get("sensitive_service_count", 0)

        score = 0.0
        explanations = []

        if is_ext == 1:
            score += 10.0
            explanations.append("Endpoint is directly exposed to external / internet routes")

        if priv_ports > 0:
            score += min(priv_ports * 5.0, 10.0)
            explanations.append(f"{priv_ports} privileged administration or file service port(s) active (e.g. MSRPC/SMB/RDP)")

        if sens_ports > priv_ports:
            score += min((sens_ports - priv_ports) * 2.5, 5.0)
            explanations.append(f"{sens_ports} sensitive network application listener(s) identified")

        clamped = min(score, cls.WEIGHT_EXPOSURE_MAX)
        return round(clamped, 1), explanations

    @classmethod
    def calculate_criticality_component(
        cls,
        asset_features: Dict[str, Any]
    ) -> (float, List[str]):
        """Calculates asset criticality component (Max 20.0)."""
        crit_val = asset_features.get("asset_criticality", 2.0)
        crit_name = "Medium"
        if crit_val >= 4.0:
            crit_name = "Critical"
        elif crit_val >= 3.0:
            crit_name = "High"
        elif crit_val <= 1.0:
            crit_name = "Low"

        score = cls.CRITICALITY_POINTS.get(crit_name, 10.0)
        explanations = [f"Asset assigned business criticality level: {crit_name}"]
        return round(score, 1), explanations

    @classmethod
    def calculate_behavioral_component(
        cls,
        behavioral_features: Dict[str, Any]
    ) -> (float, List[str]):
        """Calculates behavioral deviation component (Max 15.0)."""
        base_status = behavioral_features.get("baseline_status", "insufficient_data")
        if base_status != "established":
            return 0.0, ["Behavioral risk: Baseline not established (insufficient historical data)"]

        conn_dev = behavioral_features.get("connection_rate_deviation", 1.0)
        dst_dev = behavioral_features.get("destination_count_deviation", 1.0)

        score = 0.0
        explanations = []

        if conn_dev >= 3.0:
            score += 10.0
            explanations.append(f"Network connection rate is {conn_dev}x above historical baseline")
        elif conn_dev >= 2.0:
            score += 5.0
            explanations.append(f"Network connection rate is elevated ({conn_dev}x above baseline)")

        if dst_dev >= 2.0:
            score += 5.0
            explanations.append(f"Destination diversity is elevated ({dst_dev}x above baseline)")

        if not explanations:
            explanations.append("Network flow activity is within normal historical baseline")

        clamped = min(score, cls.WEIGHT_BEHAVIORAL_MAX)
        return round(clamped, 1), explanations

    @classmethod
    async def assess_asset_risk(cls, db: AsyncSession, asset_id: int) -> RiskAssessment:
        """
        Executes deterministic risk scoring for an asset.
        Constructs and persists a new RiskAssessment record with evidence trail.
        """
        # Ensure fresh feature extraction
        feature_set = await FeatureEngineeringService.generate_feature_set(db, asset_id)

        vuln_score, vuln_exp = cls.calculate_vulnerability_component(feature_set.vuln_features)
        expo_score, expo_exp = cls.calculate_exposure_component(feature_set.exposure_features)
        crit_score, crit_exp = cls.calculate_criticality_component(feature_set.asset_features)
        behav_score, behav_exp = cls.calculate_behavioral_component(feature_set.behavioral_features)

        total_score = round(vuln_score + expo_score + crit_score + behav_score, 1)
        total_score = min(max(total_score, 0.0), 100.0)
        risk_level = cls.classify_risk_level(total_score)

        all_explanations = vuln_exp + expo_exp + crit_exp + behav_exp

        assessment = RiskAssessment(
            asset_id=asset_id,
            timestamp=datetime.now(timezone.utc),
            methodology_version=cls.METHODOLOGY_VERSION,
            risk_score=total_score,
            risk_level=risk_level,
            vulnerability_component=vuln_score,
            exposure_component=expo_score,
            criticality_component=crit_score,
            behavioral_component=behav_score,
            explanation_list=all_explanations
        )

        db.add(assessment)

        # Update primary Asset risk_score column
        asset_res = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = asset_res.scalars().first()
        if asset:
            asset.risk_score = total_score

        await db.commit()
        await db.refresh(assessment)
        return assessment
