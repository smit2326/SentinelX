from pydantic import BaseModel
from typing import List, Dict, Any
from datetime import datetime
from app.schemas.asset import AssetOut
from app.schemas.vulnerability import VulnerabilityOut
from app.schemas.alert import AlertOut

class ExecutiveReport(BaseModel):
    generated_at: datetime
    platform_name: str = "SENTINEL-X Security Platform"
    version: str = "1.0.0"
    overall_risk_score: float
    risk_level: str # LOW, MODERATE, ELEVATED, CRITICAL
    total_assets: int
    online_assets: int
    quarantined_assets: int
    cctv_iot_devices: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    active_alerts: int
    top_vulnerable_assets: List[Dict[str, Any]]
    recent_critical_alerts: List[Dict[str, Any]]
    compliance_posture: Dict[str, Any]
    remediation_recommendations: List[str]
