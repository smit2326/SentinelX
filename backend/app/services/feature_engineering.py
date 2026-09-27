"""
Phase 3 Feature Engineering Engine for SENTINEL-X.
Transforms raw asset, vulnerability, and network telemetry into
versioned numerical and categorical features for risk scoring and ML models.
Feature Version: v1.0
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.network import NetworkConnection, NetworkPacketEvent
from app.models.analytics import FeatureSet, BehavioralBaseline


class FeatureEngineeringService:
    """
    Computes standard, versioned security features across 6 distinct categories:
    Asset, Vulnerability, Exposure, Network, Behavioral, and Time Windows.
    """

    FEATURE_VERSION = "v1.0"
    PRIVILEGED_PORTS = {135, 445, 3389, 22, 23, 21}
    WEB_PORTS = {80, 443, 8080, 8443}

    @classmethod
    def extract_asset_features(cls, asset: Asset, vulns: List[Vulnerability]) -> Dict[str, Any]:
        """Extracts structural asset inventory and posture features."""
        ports = asset.open_ports if isinstance(asset.open_ports, list) else []
        services = asset.services if isinstance(asset.services, list) else []

        crit_map = {"Low": 1.0, "Medium": 2.0, "High": 3.0, "Critical": 4.0}
        criticality_val = crit_map.get(getattr(asset, "criticality", "Medium"), 2.0)

        missing_patches = sum(1 for v in vulns if getattr(v, "patch_available", True))

        return {
            "number_of_open_ports": len(ports),
            "number_of_services": len(services),
            "number_of_installed_software": len(services),
            "number_of_known_vulnerabilities": len(vulns),
            "number_of_critical_vulnerabilities": sum(1 for v in vulns if v.severity == "CRITICAL"),
            "number_of_high_vulnerabilities": sum(1 for v in vulns if v.severity == "HIGH"),
            "number_of_medium_vulnerabilities": sum(1 for v in vulns if v.severity == "MEDIUM"),
            "number_of_low_vulnerabilities": sum(1 for v in vulns if v.severity == "LOW"),
            "number_of_missing_patches": missing_patches,
            "asset_criticality": criticality_val
        }

    @classmethod
    def extract_vulnerability_features(cls, vulns: List[Vulnerability]) -> Dict[str, Any]:
        """Extracts CVSS, exploitability, and vulnerability density features."""
        if not vulns:
            return {
                "critical_cve_count": 0,
                "high_cve_count": 0,
                "medium_cve_count": 0,
                "low_cve_count": 0,
                "max_cvss": 0.0,
                "average_cvss": 0.0,
                "exploitable_vulnerability_count": 0,
                "unpatched_vulnerability_count": 0,
                "vulnerability_age_days": 0.0,
                "affected_service_count": 0
            }

        scores = [v.cvss_score for v in vulns if v.cvss_score is not None]
        max_cvss = max(scores) if scores else 0.0
        avg_cvss = round(sum(scores) / len(scores), 2) if scores else 0.0

        now = datetime.now(timezone.utc)
        ages = []
        for v in vulns:
            if v.discovered_at:
                disc_tz = v.discovered_at if v.discovered_at.tzinfo else v.discovered_at.replace(tzinfo=timezone.utc)
                ages.append((now - disc_tz).total_seconds() / 86400.0)
        avg_age = round(sum(ages) / len(ages), 1) if ages else 0.0

        affected_services = {v.affected_service for v in vulns if v.affected_service}

        return {
            "critical_cve_count": sum(1 for v in vulns if v.severity == "CRITICAL"),
            "high_cve_count": sum(1 for v in vulns if v.severity == "HIGH"),
            "medium_cve_count": sum(1 for v in vulns if v.severity == "MEDIUM"),
            "low_cve_count": sum(1 for v in vulns if v.severity == "LOW"),
            "max_cvss": max_cvss,
            "average_cvss": avg_cvss,
            "exploitable_vulnerability_count": sum(1 for v in vulns if getattr(v, "exploit_available", False)),
            "unpatched_vulnerability_count": sum(1 for v in vulns if getattr(v, "patch_available", True)),
            "vulnerability_age_days": avg_age,
            "affected_service_count": len(affected_services)
        }

    @classmethod
    def extract_exposure_features(cls, asset: Asset) -> Dict[str, Any]:
        """Extracts reachability, external surface, and privileged port exposures."""
        ports = asset.open_ports if isinstance(asset.open_ports, list) else []
        port_numbers = set()
        for p in ports:
            p_num = p.get("port") if isinstance(p, dict) else p
            if isinstance(p_num, int):
                port_numbers.add(p_num)

        is_ext = getattr(asset, "is_external", False) or not (
            asset.ip_address.startswith("10.") or
            asset.ip_address.startswith("192.168.") or
            asset.ip_address.startswith("172.") or
            asset.ip_address in ["127.0.0.1", "localhost"]
        )

        priv_ports = port_numbers.intersection(cls.PRIVILEGED_PORTS)
        web_ports = port_numbers.intersection(cls.WEB_PORTS)

        return {
            "internet_exposed": 1 if is_ext else 0,
            "externally_reachable_service_count": len(port_numbers) if is_ext else 0,
            "externally_reachable_port_count": len(port_numbers) if is_ext else 0,
            "privileged_service_count": len(priv_ports),
            "sensitive_service_count": len(priv_ports.union(web_ports))
        }

    @classmethod
    def extract_network_features(cls, connections: List[NetworkConnection]) -> Dict[str, Any]:
        """Extracts connection density, protocol distribution, and volume statistics."""
        if not connections:
            return {
                "total_connections": 0,
                "connections_per_minute": 0.0,
                "connections_per_hour": 0.0,
                "packets_sent": 0,
                "packets_received": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "unique_source_ips": 0,
                "unique_destination_ips": 0,
                "unique_destination_ports": 0,
                "tcp_connection_count": 0,
                "udp_connection_count": 0,
                "dns_request_count": 0,
                "http_connection_count": 0,
                "https_connection_count": 0,
                "failed_connection_count": 0
            }

        total_conns = len(connections)
        total_packets = sum(c.packet_count or 1 for c in connections)
        total_bytes = sum(c.byte_count or 64 for c in connections)

        unique_src = {c.source_ip for c in connections}
        unique_dst = {c.destination_ip for c in connections}
        unique_ports = {c.destination_port for c in connections if c.destination_port}

        tcp_cnt = sum(1 for c in connections if (c.protocol or "").upper() == "TCP")
        udp_cnt = sum(1 for c in connections if (c.protocol or "").upper() == "UDP")
        dns_cnt = sum(1 for c in connections if c.destination_port == 53 or (c.service_inferred or "").upper() == "DNS")
        http_cnt = sum(1 for c in connections if c.destination_port in [80, 8080])
        https_cnt = sum(1 for c in connections if c.destination_port in [443, 8443])

        return {
            "total_connections": total_conns,
            "connections_per_minute": round(total_conns / 60.0, 2),
            "connections_per_hour": float(total_conns),
            "packets_sent": int(total_packets * 0.5),
            "packets_received": int(total_packets * 0.5),
            "bytes_sent": int(total_bytes * 0.5),
            "bytes_received": int(total_bytes * 0.5),
            "unique_source_ips": len(unique_src),
            "unique_destination_ips": len(unique_dst),
            "unique_destination_ports": len(unique_ports),
            "tcp_connection_count": tcp_cnt,
            "udp_connection_count": udp_cnt,
            "dns_request_count": dns_cnt,
            "http_connection_count": http_cnt,
            "https_connection_count": https_cnt,
            "failed_connection_count": 0
        }

    @classmethod
    def extract_behavioral_features(
        cls,
        net_feat: Dict[str, Any],
        baseline: Optional[BehavioralBaseline]
    ) -> Dict[str, Any]:
        """Calculates statistical deviations from the established behavioral baseline."""
        if not baseline or baseline.status != "established" or baseline.normal_conn_per_hour <= 0:
            return {
                "deviation_from_baseline_traffic": 1.0,
                "connection_rate_deviation": 1.0,
                "dns_rate_deviation": 1.0,
                "destination_count_deviation": 1.0,
                "new_destination_count": 0,
                "new_port_count": 0,
                "failed_connection_ratio": 0.0,
                "inbound_outbound_ratio": 1.0,
                "baseline_status": "insufficient_data"
            }

        cur_conns = float(net_feat["total_connections"])
        cur_dns = float(net_feat["dns_request_count"])
        cur_dsts = float(net_feat["unique_destination_ips"])

        conn_dev = round(cur_conns / max(baseline.normal_conn_per_hour, 1.0), 2)
        dns_dev = round(cur_dns / max(baseline.normal_dns_per_hour, 1.0), 2)
        dst_dev = round(cur_dsts / max(baseline.normal_destinations, 1.0), 2)

        return {
            "deviation_from_baseline_traffic": conn_dev,
            "connection_rate_deviation": conn_dev,
            "dns_rate_deviation": dns_dev,
            "destination_count_deviation": dst_dev,
            "new_destination_count": max(0, int(cur_dsts - baseline.normal_destinations)),
            "new_port_count": 0,
            "failed_connection_ratio": 0.0,
            "inbound_outbound_ratio": 1.0,
            "baseline_status": "established"
        }

    @classmethod
    def extract_time_windows(
        cls,
        connections: List[NetworkConnection],
        events: List[NetworkPacketEvent]
    ) -> Dict[str, Any]:
        """Calculates rolling time-window feature aggregations (5m, 15m, 1h, 24h)."""
        now = datetime.now(timezone.utc)

        def count_in_window(window_delta: timedelta) -> Dict[str, int]:
            cutoff = now - window_delta
            win_conns = [
                c for c in connections
                if c.last_seen and (
                    c.last_seen if c.last_seen.tzinfo else c.last_seen.replace(tzinfo=timezone.utc)
                ) >= cutoff
            ]
            win_events = [
                e for e in events
                if e.timestamp and (
                    e.timestamp if e.timestamp.tzinfo else e.timestamp.replace(tzinfo=timezone.utc)
                ) >= cutoff
            ]
            return {
                "connection_count": len(win_conns),
                "event_count": len(win_events),
                "unique_destinations": len({c.destination_ip for c in win_conns})
            }

        return {
            "window_5m": count_in_window(timedelta(minutes=5)),
            "window_15m": count_in_window(timedelta(minutes=15)),
            "window_1h": count_in_window(timedelta(hours=1)),
            "window_24h": count_in_window(timedelta(hours=24)),
        }

    @classmethod
    async def generate_feature_set(cls, db: AsyncSession, asset_id: int) -> FeatureSet:
        """
        Executes the end-to-end feature extraction pipeline for a given asset
        and persists the versioned FeatureSet record to the database.
        """
        asset_res = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = asset_res.scalars().first()
        if not asset:
            raise ValueError(f"Asset ID {asset_id} does not exist.")

        # Gather real Phase 1 vulnerabilities
        vuln_res = await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset_id))
        vulns = vuln_res.scalars().all()

        # Gather real Phase 2 network traffic for this asset
        conn_res = await db.execute(
            select(NetworkConnection).where(
                (NetworkConnection.source_ip == asset.ip_address) |
                (NetworkConnection.destination_ip == asset.ip_address)
            )
        )
        conns = conn_res.scalars().all()

        evt_res = await db.execute(
            select(NetworkPacketEvent).where(
                (NetworkPacketEvent.source_ip == asset.ip_address) |
                (NetworkPacketEvent.destination_ip == asset.ip_address)
            )
        )
        events = evt_res.scalars().all()

        # Gather baseline if present
        base_res = await db.execute(select(BehavioralBaseline).where(BehavioralBaseline.asset_id == asset_id))
        baseline = base_res.scalars().first()

        # Extract all 6 categories
        asset_feat = cls.extract_asset_features(asset, vulns)
        vuln_feat = cls.extract_vulnerability_features(vulns)
        expo_feat = cls.extract_exposure_features(asset)
        net_feat = cls.extract_network_features(conns)
        behav_feat = cls.extract_behavioral_features(net_feat, baseline)
        win_feat = cls.extract_time_windows(conns, events)

        # Build flat numerical vector for ML models
        flat_vector: Dict[str, float] = {
            **{f"asset_{k}": float(v) for k, v in asset_feat.items() if isinstance(v, (int, float))},
            **{f"vuln_{k}": float(v) for k, v in vuln_feat.items() if isinstance(v, (int, float))},
            **{f"expo_{k}": float(v) for k, v in expo_feat.items() if isinstance(v, (int, float))},
            **{f"net_{k}": float(v) for k, v in net_feat.items() if isinstance(v, (int, float))},
            **{f"behav_{k}": float(v) for k, v in behav_feat.items() if isinstance(v, (int, float))},
        }

        feature_set = FeatureSet(
            asset_id=asset_id,
            timestamp=datetime.now(timezone.utc),
            feature_version=cls.FEATURE_VERSION,
            asset_features=asset_feat,
            vuln_features=vuln_feat,
            exposure_features=expo_feat,
            network_features=net_feat,
            behavioral_features=behav_feat,
            window_features=win_feat,
            feature_vector=flat_vector
        )

        db.add(feature_set)
        await db.commit()
        await db.refresh(feature_set)
        return feature_set
