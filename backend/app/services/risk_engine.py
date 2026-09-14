from typing import List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnSeverity
from app.models.alert import Alert, AlertSeverity

HIGH_RISK_PORTS = {
    21: 15.0,  # FTP (plain)
    23: 25.0,  # Telnet
    445: 20.0, # SMB
    3389: 15.0,# RDP
    554: 10.0, # RTSP (CCTV video feed stream)
    8080: 5.0, # HTTP Alt
    1433: 15.0,# MSSQL
    3306: 10.0,# MySQL
    27017: 20.0# MongoDB
}

def calculate_asset_risk(asset: Asset, vulns: List[Vulnerability], alerts: List[Alert]) -> float:
    base_score = 10.0
    
    # 1. Port exposures
    if asset.open_ports and isinstance(asset.open_ports, list):
        for port_obj in asset.open_ports:
            p_num = port_obj.get("port")
            if p_num in HIGH_RISK_PORTS:
                base_score += HIGH_RISK_PORTS[p_num]
            else:
                base_score += 2.0
    
    # 2. Vulnerability CVSS impact
    for v in vulns:
        if v.status in ["OPEN", "INVESTIGATING"]:
            if v.severity == VulnSeverity.CRITICAL.value:
                base_score += v.cvss_score * 3.0
            elif v.severity == VulnSeverity.HIGH.value:
                base_score += v.cvss_score * 2.0
            elif v.severity == VulnSeverity.MEDIUM.value:
                base_score += v.cvss_score * 1.0
            else:
                base_score += 1.0
    
    # 3. Active Threat Alerts
    for a in alerts:
        if a.status in ["ACTIVE", "INVESTIGATING"]:
            if a.severity == AlertSeverity.CRITICAL.value:
                base_score += 25.0
            elif a.severity == AlertSeverity.HIGH.value:
                base_score += 15.0
            elif a.severity == AlertSeverity.MEDIUM.value:
                base_score += 5.0
    
    # 4. IoT/CCTV specialized risk
    if (asset.is_iot or asset.is_cctv) and asset.firmware_version and "v1." in asset.firmware_version:
        base_score += 15.0 # Outdated IoT firmware penalty
    
    # 5. Quarantine status reduction (mitigation control)
    if asset.is_quarantined:
        base_score = max(5.0, base_score * 0.3)
        
    return min(100.0, round(base_score, 1))

def get_risk_grade(score: float) -> Tuple[str, str]:
    if score >= 80.0:
        return "CRITICAL", "F"
    elif score >= 60.0:
        return "HIGH", "D"
    elif score >= 40.0:
        return "MODERATE", "C"
    elif score >= 20.0:
        return "ELEVATED", "B"
    else:
        return "LOW", "A"

async def calculate_global_network_risk(db: AsyncSession) -> Dict[str, Any]:
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()
    
    if not assets:
        return {
            "overall_score": 0.0,
            "risk_level": "LOW",
            "grade": "A+",
            "total_assets": 0,
            "quarantined": 0,
            "critical_count": 0
        }
    
    total_score = sum(a.risk_score for a in assets)
    avg_score = round(total_score / len(assets), 1)
    
    # Boost if any critical alerts are active
    crit_alerts_res = await db.execute(select(func.count(Alert.id)).where(Alert.severity == "CRITICAL", Alert.status == "ACTIVE"))
    crit_alert_count = crit_alerts_res.scalar() or 0
    
    adjusted_score = min(100.0, round(avg_score + (crit_alert_count * 5.0), 1))
    level, grade = get_risk_grade(adjusted_score)
    
    quarantined_count = sum(1 for a in assets if a.is_quarantined)
    critical_assets = sum(1 for a in assets if a.risk_score >= 75.0)
    
    return {
        "overall_score": adjusted_score,
        "risk_level": level,
        "grade": grade,
        "total_assets": len(assets),
        "quarantined": quarantined_count,
        "critical_assets": critical_assets,
        "active_critical_alerts": crit_alert_count
    }
