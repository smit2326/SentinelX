import asyncio
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.core.database import Base, engine, AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.system_config import SystemConfig
from app.models.network import (
    NetworkCapture,
    NetworkPacketEvent,
    NetworkConnection,
    CorrelatedFinding
)
from app.models.analytics import (
    FeatureSet,
    BehavioralBaseline,
    RiskAssessment,
    ModelVersion,
    MLPrediction,
    EvaluationResult,
    DatasetRecord
)
from app.core.logger import logger

async def clear_demo_data(db: AsyncSession):
    """Purges all demo/synthetic assets, fake alerts, and synthetic captures."""
    logger.info("Purging all demo assets, synthetic alerts, and demo captures...")
    await db.execute(delete(CorrelatedFinding))
    await db.execute(delete(NetworkPacketEvent))
    await db.execute(delete(NetworkConnection))
    await db.execute(delete(NetworkCapture))
    await db.execute(delete(Alert))
    await db.execute(delete(Vulnerability))
    await db.execute(delete(Asset))
    await db.commit()
    logger.info("Demo asset and synthetic incident data completely removed.")

def ensure_asset_columns(conn):
    """Adds missing Phase 3 Data Quality columns to existing SQLite assets table if needed."""
    try:
        res = conn.exec_driver_sql("PRAGMA table_info(assets)")
        columns = [row[1] for row in res.fetchall()]
        new_cols = [
            ("os_build", "VARCHAR(50)"),
            ("data_source", "VARCHAR(100) DEFAULT 'Windows Collector'"),
            ("confidence", "VARCHAR(50) DEFAULT 'High'"),
            ("collection_time", "DATETIME"),
            ("data_quality", "VARCHAR(50) DEFAULT 'Complete'"),
            ("quality_metadata", "JSON DEFAULT '{}'")
        ]
        for col_name, col_type in new_cols:
            if col_name not in columns:
                conn.exec_driver_sql(f"ALTER TABLE assets ADD COLUMN {col_name} {col_type}")
    except Exception as e:
        logger.warning(f"Column migration check notice: {e}")

async def init_and_seed_db():
    logger.info("Initializing database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(ensure_asset_columns)
    
    async with AsyncSessionLocal() as db:
        # Check if users already seeded
        user_check = await db.execute(select(User))
        if not user_check.scalars().first():
            logger.info("Seeding SENTINEL-X Administrative Accounts...")
            users = [
                User(
                    email="admin@sentinel-x.sec",
                    hashed_password=get_password_hash("SentinelAdmin2026!"),
                    full_name="Alex Vance (Super Admin)",
                    role=UserRole.ADMIN.value,
                    avatar_url="https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80",
                    is_active=True
                ),
                User(
                    email="analyst@sentinel-x.sec",
                    hashed_password=get_password_hash("SentinelAnalyst2026!"),
                    full_name="Sarah Chen (Lead SOC Analyst)",
                    role=UserRole.ANALYST.value,
                    avatar_url="https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80",
                    is_active=True
                ),
                User(
                    email="auditor@sentinel-x.sec",
                    hashed_password=get_password_hash("SentinelAuditor2026!"),
                    full_name="Marcus Brody (Compliance Auditor)",
                    role=UserRole.AUDITOR.value,
                    avatar_url="https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=150&auto=format&fit=crop&q=80",
                    is_active=True
                )
            ]
            db.add_all(users)
            await db.flush()

        # Check system configs
        cfg_check = await db.execute(select(SystemConfig))
        if not cfg_check.scalars().first():
            configs = [
                SystemConfig(key="scanner.default_subnet", value="127.0.0.1/32", category="scanner", description="Primary CIDR range for network asset discovery probes"),
                SystemConfig(key="scanner.rate_limit_pps", value="1000", category="scanner", description="Maximum packets per second for discovery engine"),
                SystemConfig(key="scanner.nmap_timing_template", value="T4", category="scanner", description="Scanner timing aggression (T1 sneaky to T5 aggressive)"),
                SystemConfig(key="scanner.cctv_rtsp_deep_scan", value="true", category="scanner", description="Enable active RTSP/ONVIF port banner and auth probing"),
                SystemConfig(key="siem.webhook_url", value="https://siem.corp.sentinel.sec/hooks/aegis-alerts", category="notification", description="External SIEM / Webhook target for critical incident dispatch"),
                SystemConfig(key="siem.slack_alert_channel", value="#soc-critical-alerts", category="notification", description="Slack / Discord channel webhook for immediate analyst notification"),
                SystemConfig(key="threat_intel.nvd_api_key", value="cve-api-key-live-sentinel-2026-prod", category="threat_intel", description="National Vulnerability Database (NVD) v2 API key", is_secret=True),
                SystemConfig(key="threat_intel.auto_correlate", value="true", category="threat_intel", description="Automatically correlate newly discovered service banners with open CVE feeds")
            ]
            db.add_all(configs)
            await db.commit()

        # Always purge any leftover demo assets if present
        demo_assets = await db.execute(
            select(Asset).where(Asset.ip_address.in_(["192.168.1.1", "192.168.1.10", "192.168.1.20", "192.168.1.25", "192.168.1.45", "192.168.1.46", "192.168.1.72", "192.168.1.150"]))
        )
        if demo_assets.scalars().first():
            await clear_demo_data(db)

        # Ensure local laptop asset has complete Phase 3 Data Quality passport
        laptop_stmt = select(Asset).where(Asset.ip_address.in_(["127.0.0.1", "localhost"]))
        laptop_res = await db.execute(laptop_stmt)
        laptop_asset = laptop_res.scalars().first()
        if laptop_asset:
            laptop_asset.os_name = "Windows 11"
            laptop_asset.os_build = "26100"
            laptop_asset.data_source = "Windows Collector"
            laptop_asset.confidence = "High"
            laptop_asset.collection_time = datetime.now(timezone.utc)
            laptop_asset.data_quality = "Complete"
            laptop_asset.quality_metadata = {
                "os": "Windows 11",
                "os_build": "26100",
                "source": "Windows Collector",
                "confidence": "High",
                "collection_time": "2026-09-27",
                "data_quality": "Complete",
                "completeness_score": 100.0,
                "missing_fields": [],
                "inferred_fields": [],
                "lineage_summary": "Source: Windows Collector (High Confidence) | Quality: Complete (100.0% Complete)"
            }
            await db.commit()

if __name__ == "__main__":
    asyncio.run(init_and_seed_db())
