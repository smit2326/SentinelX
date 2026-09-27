"""
Phase 3 Canonical Security Normalization Service for SENTINEL-X.
Translates heterogeneous telemetry from Nmap, Windows Collector, OpenVAS, and TShark
into canonical representations while maintaining strict source provenance.
"""

import re
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from app.services.data_cleaning_pipeline import DataCleaningPipeline


class CanonicalNormalizer:
    """
    Normalizes disparate vendor, scanner, and sensor telemetry into unified internal schemas.
    Preserves original raw values alongside normalized fields for provenance and auditability.
    """

    SERVICE_CANONICAL_MAP = {
        r"(?i)microsoft[- ]windows[- ]rpc|msrpc|ms-rpc|windows[- ]rpc": "MSRPC",
        r"(?i)microsoft[- ]ds|smb|smbv[123]|netbios-ssn": "SMBv3",
        r"(?i)http|http-proxy|world[- ]wide[- ]web": "HTTP",
        r"(?i)https|ssl/http|http-alt": "HTTPS",
        r"(?i)ssh|openssh": "SSH",
        r"(?i)domain|dns": "DNS",
        r"(?i)ms-wbt-server|rdp|terminal[- ]services": "RDP",
        r"(?i)rtsp|real[- ]time[- ]streaming[- ]protocol": "RTSP",
        r"(?i)onvif": "ONVIF",
        r"(?i)ftp": "FTP",
        r"(?i)smtp": "SMTP",
    }

    PROTOCOL_CANONICAL_MAP = {
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "tcp": "TCP",
        "udp": "UDP",
        "icmp": "ICMP",
        "arp": "ARP",
        "dns": "DNS",
        "tls": "TLS",
        "http": "HTTP",
        "rtsp": "RTSP",
        "smb": "SMB",
    }

    @classmethod
    def normalize_service(cls, raw_service: Optional[str], port: Optional[int] = None) -> Dict[str, Any]:
        """
        Normalizes diverse service names into canonical representations.
        Example: 'Microsoft Windows RPC' -> 'MSRPC'
        """
        if not raw_service or not str(raw_service).strip():
            inferred = "unknown"
            if port == 445:
                inferred = "SMBv3"
            elif port == 135:
                inferred = "MSRPC"
            elif port == 80:
                inferred = "HTTP"
            elif port == 443:
                inferred = "HTTPS"
            return {
                "raw_service": raw_service,
                "canonical_service": inferred,
                "is_inferred": inferred != "unknown",
                "normalization_applied": True
            }

        cleaned = str(raw_service).strip()
        for pattern, canonical in cls.SERVICE_CANONICAL_MAP.items():
            if re.search(pattern, cleaned):
                return {
                    "raw_service": raw_service,
                    "canonical_service": canonical,
                    "is_inferred": False,
                    "normalization_applied": True
                }

        return {
            "raw_service": raw_service,
            "canonical_service": cleaned.upper(),
            "is_inferred": False,
            "normalization_applied": False
        }

    @classmethod
    def normalize_protocol(cls, raw_protocol: Optional[str]) -> str:
        """Converts protocol representations (numbers or strings) into standard uppercase format."""
        if not raw_protocol:
            return "UNKNOWN"
        cleaned = str(raw_protocol).strip().lower()
        return cls.PROTOCOL_CANONICAL_MAP.get(cleaned, cleaned.upper())

    @classmethod
    def normalize_event_provenance(
        cls,
        raw_event: Dict[str, Any],
        source: str = "TShark"
    ) -> Dict[str, Any]:
        """
        Stamps a security event with canonical network primitives and source provenance.
        """
        src_ip_val = DataCleaningPipeline.validate_ip(str(raw_event.get("source_ip", "")))
        dst_ip_val = DataCleaningPipeline.validate_ip(str(raw_event.get("destination_ip", "")))

        proto = cls.normalize_protocol(str(raw_event.get("protocol", "TCP")))
        port = raw_event.get("destination_port")
        srv = cls.normalize_service(raw_event.get("service_inferred"), port=port)

        now_utc = datetime.now(timezone.utc).isoformat()
        return {
            "source": source,
            "ingested_at": now_utc,
            "source_ip": src_ip_val["canonical_ip"] if src_ip_val["is_valid"] else "unknown",
            "destination_ip": dst_ip_val["canonical_ip"] if dst_ip_val["is_valid"] else "unknown",
            "protocol": proto,
            "destination_port": port,
            "canonical_service": srv["canonical_service"],
            "raw_provenance": {
                "original_service": raw_event.get("service_inferred"),
                "original_protocol": raw_event.get("protocol"),
                "collector": source
            }
        }
