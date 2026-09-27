"""
Phase 3 Behavioral Baseline Engine for SENTINEL-X.
Calculates deterministic operational baselines for assets based on observed network flows.
Adheres strictly to the principle: If insufficient historical data exists,
record status = 'insufficient_data'; never manufacture a fake baseline.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.network import NetworkConnection
from app.models.analytics import BehavioralBaseline
from app.core.logger import logger


class BaselineEngine:
    """
    Constructs and evaluates asset behavioral baselines.
    Distinguishes established baselines from insufficient historical records.
    """

    MINIMUM_SAMPLES_REQUIRED = 3

    @classmethod
    async def compute_asset_baseline(cls, db: AsyncSession, asset_id: int) -> BehavioralBaseline:
        """
        Computes the statistical baseline for an asset from historical network connections.
        If history is inadequate, assigns status = 'insufficient_data'.
        """
        asset_res = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = asset_res.scalars().first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} does not exist.")

        # Query connections for this asset
        conn_res = await db.execute(
            select(NetworkConnection).where(
                (NetworkConnection.source_ip == asset.ip_address) |
                (NetworkConnection.destination_ip == asset.ip_address)
            )
        )
        conns = conn_res.scalars().all()

        base_res = await db.execute(
            select(BehavioralBaseline).where(BehavioralBaseline.asset_id == asset_id)
        )
        baseline = base_res.scalars().first()

        sample_count = len(conns)

        if not baseline:
            baseline = BehavioralBaseline(
                asset_id=asset_id,
                baseline_version="v1.0",
                sample_count=sample_count,
                status="insufficient_data",
                created_at=datetime.now(timezone.utc)
            )
            db.add(baseline)

        baseline.sample_count = sample_count
        baseline.updated_at = datetime.now(timezone.utc)

        # Check if historical depth is sufficient
        if sample_count < cls.MINIMUM_SAMPLES_REQUIRED:
            baseline.status = "insufficient_data"
            baseline.normal_conn_per_hour = 0.0
            baseline.normal_dns_per_hour = 0.0
            baseline.normal_destinations = 0.0
            baseline.normal_bytes_per_hour = 0.0
            logger.info(f"Asset {asset.hostname or asset.ip_address}: Insufficient data for baseline ({sample_count} samples).")
        else:
            # Calculate empirical averages
            total_bytes = sum(c.byte_count or 64 for c in conns)
            unique_dst = len({c.destination_ip for c in conns})
            dns_count = sum(1 for c in conns if c.destination_port == 53 or (c.service_inferred or "").upper() == "DNS")

            # Hourly rate based on sample density
            baseline.normal_conn_per_hour = float(sample_count)
            baseline.normal_dns_per_hour = float(dns_count)
            baseline.normal_destinations = float(unique_dst)
            baseline.normal_bytes_per_hour = float(total_bytes)
            baseline.status = "established"
            logger.info(f"Asset {asset.hostname or asset.ip_address}: Baseline established with {sample_count} flows.")

        await db.commit()
        await db.refresh(baseline)
        return baseline

    @classmethod
    def evaluate_traffic_deviation(
        cls,
        current_stats: Dict[str, Any],
        baseline: Optional[BehavioralBaseline]
    ) -> Dict[str, Any]:
        """
        Compares observed telemetry against the learned baseline.
        Returns deviation ratios and an analyst-oriented explanation.
        """
        if not baseline or baseline.status != "established" or baseline.normal_conn_per_hour <= 0:
            return {
                "has_baseline": False,
                "status": "Baseline not established",
                "deviation_ratio": 1.0,
                "is_anomalous": False,
                "explanation": "Behavioral analysis unavailable — insufficient historical data."
            }

        cur_conns = float(current_stats.get("total_connections", 0))
        cur_dns = float(current_stats.get("dns_request_count", 0))
        cur_dsts = float(current_stats.get("unique_destination_ips", 0))

        conn_dev = round(cur_conns / max(baseline.normal_conn_per_hour, 1.0), 2)
        dns_dev = round(cur_dns / max(baseline.normal_dns_per_hour, 1.0), 2)
        dst_dev = round(cur_dsts / max(baseline.normal_destinations, 1.0), 2)

        is_anom = conn_dev >= 2.5 or dns_dev >= 3.0 or dst_dev >= 2.5
        reasons = []
        if conn_dev >= 2.0:
            reasons.append(f"Connection rate is {conn_dev}x above historical baseline")
        if dns_dev >= 2.0:
            reasons.append(f"DNS query rate is {dns_dev}x above historical baseline")
        if dst_dev >= 2.0:
            reasons.append(f"Destination diversity is {dst_dev}x above historical baseline")

        explanation = "; ".join(reasons) if reasons else "Traffic consistent with learned baseline."

        return {
            "has_baseline": True,
            "status": "Deviation detected" if is_anom else "Within baseline",
            "deviation_ratio": conn_dev,
            "is_anomalous": is_anom,
            "explanation": explanation
        }
