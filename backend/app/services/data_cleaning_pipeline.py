"""
Phase 3 Data Cleaning & Hygiene Pipeline for SENTINEL-X.
Cleans raw security telemetry, normalizes OS/software formats,
handles missing values without synthetic hallucination, validates network primitives,
and normalizes timestamps into canonical UTC representations.
"""

import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.core.logger import logger
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.network import NetworkConnection, NetworkPacketEvent
from app.services.data_quality_layer import DataQualityLayer

# ---------------------------------------------------------------------------
# OS Normalization Signatures
# ---------------------------------------------------------------------------
OS_SIGNATURES = [
    # Windows Desktop & Server
    (r"(?i)windows\s*11|win\s*11", "Windows", "Microsoft Windows 11", "11"),
    (r"(?i)windows\s*10|win\s*10", "Windows", "Microsoft Windows 10", "10"),
    (r"(?i)windows\s*server\s*2025", "Windows", "Microsoft Windows Server 2025", "2025"),
    (r"(?i)windows\s*server\s*2022", "Windows", "Microsoft Windows Server 2022", "2022"),
    (r"(?i)windows\s*server\s*2019", "Windows", "Microsoft Windows Server 2019", "2019"),
    (r"(?i)windows\s*server\s*2016", "Windows", "Microsoft Windows Server 2016", "2016"),
    (r"(?i)windows\s*8\.1", "Windows", "Microsoft Windows 8.1", "8.1"),
    (r"(?i)windows\s*7", "Windows", "Microsoft Windows 7", "7"),
    (r"(?i)windows", "Windows", "Microsoft Windows", None),
    
    # Linux Distributions
    (r"(?i)ubuntu\s*([0-9\.]+)?", "Linux", "Ubuntu Linux", None),
    (r"(?i)debian\s*([0-9\.]+)?", "Linux", "Debian GNU/Linux", None),
    (r"(?i)kali\s*linux", "Linux", "Kali Linux", None),
    (r"(?i)red\s*hat|rhel\s*([0-9\.]+)?", "Linux", "Red Hat Enterprise Linux", None),
    (r"(?i)centos\s*([0-9\.]+)?", "Linux", "CentOS Linux", None),
    (r"(?i)fedora\s*([0-9\.]+)?", "Linux", "Fedora Linux", None),
    (r"(?i)alpine", "Linux", "Alpine Linux", None),
    (r"(?i)arch\s*linux", "Linux", "Arch Linux", None),
    (r"(?i)linux\s*([0-9\.]+)?", "Linux", "Generic Linux", None),
    
    # Network Appliances & Routers
    (r"(?i)cisco\s*ios|ios-xe", "Network Appliance", "Cisco IOS", None),
    (r"(?i)routeros|mikrotik", "Network Appliance", "MikroTik RouterOS", None),
    (r"(?i)openwrt", "Network Appliance", "OpenWrt", None),
    (r"(?i)pfsense", "Network Appliance", "pfSense FreeBSD", None),
    (r"(?i)fortios|fortigate", "Network Appliance", "Fortinet FortiOS", None),
    (r"(?i)tp-link|archer", "Network Appliance", "TP-Link Firmware", None),
    
    # IoT & Surveillance
    (r"(?i)hikvision", "Embedded IoT", "Hikvision Embedded Linux", None),
    (r"(?i)dahua", "Embedded IoT", "Dahua Embedded Linux", None),
    (r"(?i)axis\s*camera", "Embedded IoT", "Axis Embedded Linux", None),
    
    # macOS & Unix
    (r"(?i)darwin|mac\s*os|macos|os\s*x", "macOS", "Apple macOS", None),
    (r"(?i)freebsd", "Unix", "FreeBSD", None),
    (r"(?i)openbsd", "Unix", "OpenBSD", None),
]

# ---------------------------------------------------------------------------
# MAC OUI Manufacturer Lookup (Sample Canonical Prefixes)
# ---------------------------------------------------------------------------
MAC_OUI_MAP = {
    "00:50:56": "VMware, Inc.",
    "00:0c:29": "VMware, Inc.",
    "00:15:5d": "Microsoft Hyper-V",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
    "00:18:ae": "Cisco Systems",
    "00:1c:b0": "Cisco Systems",
    "28:6f:7f": "TP-Link Corporation",
    "50:c7:bf": "TP-Link Corporation",
    "bc:ba:e1": "Hikvision Digital Technology",
    "44:19:b6": "Hikvision Digital Technology",
    "38:af:29": "Dahua Technology",
    "a4:14:37": "Dahua Technology",
    "ec:71:db": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",
    "00:1a:11": "Google, Inc."
}

# ---------------------------------------------------------------------------
# Standard Port Service Map
# ---------------------------------------------------------------------------
WELL_KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMBv3",
    554: "RTSP",
    1433: "MSSQL",
    1521: "Oracle DB",
    1900: "UPnP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8000: "HTTP-Dev",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}


class DataCleaningPipeline:
    """
    Orchestrates data cleansing, validation, normalization, and deduplication
    across raw security feeds and telemetry tables.
    """

    # -----------------------------------------------------------------------
    # Requirement A: Remove Duplicates
    # -----------------------------------------------------------------------
    @staticmethod
    def deduplicate_records(
        records: List[Dict[str, Any]],
        key_fields: List[str]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Deduplicates a collection of dictionaries based on a tuple of key fields.
        Returns deduplicated records and the count of duplicates removed.
        """
        seen_keys: Set[Tuple[Any, ...]] = set()
        unique_records: List[Dict[str, Any]] = []
        duplicates_removed = 0

        for r in records:
            composite_key = tuple(r.get(k) for k in key_fields)
            if composite_key in seen_keys:
                duplicates_removed += 1
                continue
            seen_keys.add(composite_key)
            unique_records.append(r)

        return unique_records, duplicates_removed

    # -----------------------------------------------------------------------
    # Requirement B: Normalize Operating Systems
    # -----------------------------------------------------------------------
    @staticmethod
    def normalize_os(
        raw_os: Optional[str],
        raw_version: Optional[str] = None,
        raw_build: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Normalizes unstructured OS names, versions, and builds into a canonical schema.
        """
        if not raw_os or not raw_os.strip():
            return {
                "os_family": "Unknown",
                "normalized_name": "Unknown Operating System",
                "os_version": None,
                "os_build": None,
                "confidence": 0.0,
                "is_normalized": False
            }

        text = raw_os.strip()
        os_family = "General Host"
        normalized_name = text
        extracted_version = raw_version
        extracted_build = raw_build
        matched = False

        for pattern, family, norm_title, default_ver in OS_SIGNATURES:
            m = re.search(pattern, text)
            if m:
                os_family = family
                normalized_name = norm_title
                matched = True
                if not extracted_version:
                    extracted_version = default_ver or (m.group(1) if m.groups() and m.group(1) else None)
                break

        # Attempt build extraction from text if not supplied explicitly (e.g. "Build 26100" or standalone 26100)
        if not extracted_build:
            build_match = re.search(r"(?i)(?:build\s*|(?<=\s))([0-9]{5,6})(?:\b|$)", text)
            if build_match:
                extracted_build = build_match.group(1)
            else:
                build_match_alt = re.search(r"(?i)build\s*([0-9]{4,6})", text)
                if build_match_alt:
                    extracted_build = build_match_alt.group(1)

        return {
            "os_family": os_family,
            "normalized_name": normalized_name,
            "os_version": extracted_version,
            "os_build": extracted_build,
            "confidence": 0.95 if matched else 0.40,
            "is_normalized": True
        }

    # -----------------------------------------------------------------------
    # Requirement C: Normalize Software Versions
    # -----------------------------------------------------------------------
    @staticmethod
    def normalize_software_version(raw_service_str: Optional[str]) -> Dict[str, Any]:
        """
        Extracts clean vendor, product name, and semantic version from messy banner strings.
        Example: 'OpenSSH_8.9p1 Ubuntu-3ubuntu0.6' -> Product: 'OpenSSH', Version: '8.9p1'
        """
        if not raw_service_str or not raw_service_str.strip():
            return {
                "product": "Unknown",
                "version": None,
                "major": None,
                "minor": None,
                "patch": None,
                "cpe_candidate": None
            }

        banner = raw_service_str.strip()

        # Regex for common patterns: Product/Version, Product_Version, Product Version
        match = re.search(r"^([A-Za-z0-9_\-\.\+]+)[/_ ]v?([0-9]+(?:\.[0-9]+)*(?:[a-zA-Z0-9_\-]+)?)", banner)
        if match:
            product = match.group(1).replace("_", " ").title()
            version = match.group(2)
        else:
            # Fallback version search anywhere in the string
            ver_search = re.search(r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", banner)
            version = ver_search.group(1) if ver_search else None
            product = banner.split()[0] if banner else "Unknown"

        # Semantic version components
        major, minor, patch = None, None, None
        if version:
            parts = re.findall(r"[0-9]+", version)
            if len(parts) >= 1:
                major = int(parts[0])
            if len(parts) >= 2:
                minor = int(parts[1])
            if len(parts) >= 3:
                patch = int(parts[2])

        cpe_candidate = f"cpe:/a:{product.lower().replace(' ', '_')}:{version}" if version else None

        return {
            "product": product,
            "version": version,
            "major": major,
            "minor": minor,
            "patch": patch,
            "cpe_candidate": cpe_candidate
        }

    # -----------------------------------------------------------------------
    # Requirement D: Handle Missing Values (Without Blind Replacement)
    # -----------------------------------------------------------------------
    @staticmethod
    def handle_missing_values(record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handles missing fields using deterministic domain inferences rather than
        blindly replacing with synthetic placeholders. Flags imputed vs authentic fields.
        """
        cleaned = dict(record)
        metadata_flags = cleaned.get("data_hygiene_flags", {})

        # 1. Hostname: If missing, attempt reverse DNS or keep None
        if not cleaned.get("hostname"):
            ip = cleaned.get("ip_address")
            if ip and ip not in ["127.0.0.1", "0.0.0.0"]:
                try:
                    resolved = socket.gethostbyaddr(ip)[0]
                    cleaned["hostname"] = resolved
                    metadata_flags["hostname_resolved"] = True
                except Exception: # pylint: disable=broad-exception-caught
                    cleaned["hostname"] = None
                    metadata_flags["hostname_resolved"] = False
            else:
                cleaned["hostname"] = None
                metadata_flags["hostname_resolved"] = False

        # 2. Vendor / Manufacturer: Resolve from MAC OUI if available
        mac = cleaned.get("mac_address")
        if not cleaned.get("vendor"):
            if mac and len(mac) >= 8:
                prefix = mac.lower().replace("-", ":")[:8]
                resolved_vendor = MAC_OUI_MAP.get(prefix)
                if resolved_vendor:
                    cleaned["vendor"] = resolved_vendor
                    metadata_flags["vendor_inferred_from_oui"] = True
                else:
                    cleaned["vendor"] = None
                    metadata_flags["vendor_inferred_from_oui"] = False
            else:
                cleaned["vendor"] = None
                metadata_flags["vendor_inferred_from_oui"] = False

        # 3. Device Type: Inferred strictly from open ports if missing
        if not cleaned.get("device_type") or cleaned.get("device_type") == "Unknown":
            ports = cleaned.get("open_ports", [])
            port_nums = set()
            for p in ports:
                if isinstance(p, dict) and "port" in p:
                    port_nums.add(p["port"])
                elif isinstance(p, int):
                    port_nums.add(p)

            if 554 in port_nums:
                cleaned["device_type"] = "CCTV Camera"
                metadata_flags["device_type_inferred"] = "RTSP port 554 open"
            elif any(p in port_nums for p in [135, 445, 3389]):
                cleaned["device_type"] = "Workstation"
                metadata_flags["device_type_inferred"] = "Windows RPC/SMB active"
            elif any(p in port_nums for p in [53, 1900]):
                cleaned["device_type"] = "Router"
                metadata_flags["device_type_inferred"] = "Gateway DNS/UPnP active"
            else:
                cleaned["device_type"] = "General Host"
                metadata_flags["device_type_inferred"] = "Default unclassified host"

        # 4. CVSS Score: Never fabricate a fake score. If missing, mark as unassessed.
        if "cvss_score" in cleaned and cleaned["cvss_score"] is None:
            metadata_flags["cvss_pending_assessment"] = True

        cleaned["data_hygiene_flags"] = metadata_flags
        return cleaned

    # -----------------------------------------------------------------------
    # Requirement E: Validate IP Addresses
    # -----------------------------------------------------------------------
    @staticmethod
    def validate_ip(ip_str: Optional[str]) -> Dict[str, Any]:
        """
        Validates IPv4 and IPv6 addresses.
        Returns validation status, address category, and normalized representation.
        """
        if not ip_str or not isinstance(ip_str, str):
            return {
                "is_valid": False,
                "reason": "Null or non-string input",
                "canonical_ip": None
            }

        clean_ip = ip_str.strip()
        try:
            addr = ipaddress.ip_address(clean_ip)
            return {
                "is_valid": True,
                "version": addr.version,
                "canonical_ip": str(addr),
                "is_private": addr.is_private,
                "is_loopback": addr.is_loopback,
                "is_multicast": addr.is_multicast,
                "is_reserved": addr.is_reserved,
                "is_global": addr.is_global
            }
        except ValueError as exc:
            return {
                "is_valid": False,
                "reason": f"Invalid IP syntax: {str(exc)}",
                "canonical_ip": None
            }

    # -----------------------------------------------------------------------
    # Requirement F: Validate TCP/UDP Ports
    # -----------------------------------------------------------------------
    @staticmethod
    def validate_port(port: Any, protocol: str = "tcp") -> Dict[str, Any]:
        """
        Validates whether a port is within the RFC standard TCP/UDP range (1 to 65535).
        Identifies port class (Well-Known, Registered, Ephemeral) and known service name.
        """
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            return {
                "is_valid": False,
                "reason": f"Port '{port}' cannot be parsed as an integer",
                "port_number": None
            }

        if port_num < 1 or port_num > 65535:
            return {
                "is_valid": False,
                "reason": f"Port {port_num} is outside valid RFC range [1, 65535]",
                "port_number": port_num
            }

        # Port classification
        if port_num <= 1023:
            port_class = "Well-Known"
        elif port_num <= 49151:
            port_class = "Registered"
        else:
            port_class = "Dynamic/Ephemeral"

        service_name = WELL_KNOWN_SERVICES.get(port_num, f"custom-{protocol}-{port_num}")

        return {
            "is_valid": True,
            "port_number": port_num,
            "port_class": port_class,
            "protocol": protocol.lower(),
            "standard_service": service_name
        }

    # -----------------------------------------------------------------------
    # Requirement G: Normalize Timestamps
    # -----------------------------------------------------------------------
    @staticmethod
    def normalize_timestamp(raw_timestamp: Any) -> Optional[datetime]:
        """
        Converts diverse timestamp formats (Unix epoch in s/ms/us, ISO-8601 strings,
        SQL strings) into canonical timezone-aware UTC datetime instances.
        """
        if raw_timestamp is None:
            return None

        result_dt: Optional[datetime] = None

        if isinstance(raw_timestamp, datetime):
            result_dt = raw_timestamp
        elif isinstance(raw_timestamp, (int, float)):
            val = float(raw_timestamp)
            scale = 1e6 if val > 1e14 else (1e3 if val > 1e11 else 1.0)
            result_dt = datetime.fromtimestamp(val / scale, tz=timezone.utc)
        elif isinstance(raw_timestamp, str):
            clean_str = raw_timestamp.strip()
            if clean_str.replace(".", "", 1).isdigit():
                return DataCleaningPipeline.normalize_timestamp(float(clean_str))

            if clean_str.endswith("Z"):
                clean_str = clean_str[:-1] + "+00:00"

            try:
                result_dt = datetime.fromisoformat(clean_str)
            except ValueError:
                iso_candidates = [
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S",
                    "%a, %d %b %Y %H:%M:%S %Z",
                    "%a, %d %b %Y %H:%M:%S GMT"
                ]
                for fmt in iso_candidates:
                    try:
                        result_dt = datetime.strptime(clean_str, fmt)
                        break
                    except ValueError:
                        continue

        if result_dt is not None:
            if result_dt.tzinfo is None:
                return result_dt.replace(tzinfo=timezone.utc)
            return result_dt.astimezone(timezone.utc)

        return None

    # -----------------------------------------------------------------------
    # Comprehensive Database Hygiene Execution
    # -----------------------------------------------------------------------
    @classmethod
    async def clean_database_telemetry(cls, db: AsyncSession) -> Dict[str, Any]:
        """
        Executes the entire 7-step pipeline across active Sentinel-X tables:
        1. Audits & deduplicates assets and vulnerabilities.
        2. Validates IP addresses and filters out invalid records.
        3. Validates and cleans open port registries.
        4. Normalizes OS strings and software versions.
        5. Handles missing values with domain logic.
        6. Normalizes all datetime timestamps to UTC.
        """
        report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assets_evaluated": 0,
            "assets_cleaned": 0,
            "invalid_ips_flagged": 0,
            "ports_sanitized": 0,
            "os_normalized_count": 0,
            "vulns_deduplicated": 0,
            "timestamps_normalized": 0
        }

        # --- A & E & F & B & D: Clean Assets ---
        assets_res = await db.execute(select(Asset))
        assets = assets_res.scalars().all()
        report["assets_evaluated"] = len(assets)

        seen_ips: Set[str] = set()
        duplicate_asset_ids: List[int] = []

        for asset in assets:
            # E. Validate IP
            ip_val = cls.validate_ip(asset.ip_address)
            if not ip_val["is_valid"]:
                report["invalid_ips_flagged"] += 1
                logger.warning(f"Flagged invalid IP address on Asset ID {asset.id}: {asset.ip_address}")
            else:
                asset.ip_address = ip_val["canonical_ip"]

            # A. Deduplicate by IP
            if asset.ip_address in seen_ips:
                duplicate_asset_ids.append(asset.id)
                continue
            seen_ips.add(asset.ip_address)

            # B. Normalize OS
            if asset.os_name:
                norm_os = cls.normalize_os(asset.os_name, asset.os_version)
                if norm_os["is_normalized"]:
                    asset.os_name = norm_os["normalized_name"]
                    if norm_os["os_version"]:
                        asset.os_version = norm_os["os_version"]
                    report["os_normalized_count"] += 1

            # F. Validate Open Ports
            if asset.open_ports and isinstance(asset.open_ports, list):
                valid_ports = []
                for p_entry in asset.open_ports:
                    p_num = p_entry.get("port") if isinstance(p_entry, dict) else p_entry
                    proto = p_entry.get("protocol", "tcp") if isinstance(p_entry, dict) else "tcp"
                    p_val = cls.validate_port(p_num, proto)
                    if p_val["is_valid"]:
                        valid_ports.append({
                            "port": p_val["port_number"],
                            "protocol": p_val["protocol"],
                            "service": p_val["standard_service"],
                            "state": "open"
                        })
                        report["ports_sanitized"] += 1
                asset.open_ports = valid_ports

            # D. Handle Missing Values
            asset_dict = {
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "mac_address": asset.mac_address,
                "vendor": asset.vendor,
                "device_type": asset.device_type,
                "open_ports": asset.open_ports
            }
            cleaned_asset = cls.handle_missing_values(asset_dict)
            asset.hostname = cleaned_asset["hostname"]
            asset.vendor = cleaned_asset["vendor"]
            asset.device_type = cleaned_asset["device_type"]

            # G. Normalize Timestamps
            if asset.last_scanned:
                norm_dt = cls.normalize_timestamp(asset.last_scanned)
                if norm_dt:
                    asset.last_scanned = norm_dt
                    report["timestamps_normalized"] += 1

            # Phase 3 Component 3: Data Quality & Lineage Passport
            # "Don't just clean the data and throw bad records away."
            raw_record = {
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
                "os_name": asset.os_name,
                "os_build": asset.os_build,
                "vendor": asset.vendor,
                "mac_address": asset.mac_address,
                "open_ports": asset.open_ports,
                "collection_time": asset.last_scanned
            }
            passport = DataQualityLayer.assess_record_quality(
                raw_record,
                source=asset.data_source or "Windows Collector"
            )
            asset.os_build = passport["os_build"]
            asset.data_source = passport["source"]
            asset.confidence = passport["confidence"]
            asset.data_quality = passport["data_quality"]
            asset.quality_metadata = passport
            asset.collection_time = asset.last_scanned

            report["assets_cleaned"] += 1
            report["quality_passports_generated"] = report.get("quality_passports_generated", 0) + 1

        # Delete duplicate assets if any
        if duplicate_asset_ids:
            await db.execute(delete(Asset).where(Asset.id.in_(duplicate_asset_ids)))

        # --- A & G: Deduplicate Vulnerabilities ---
        vulns_res = await db.execute(select(Vulnerability))
        vulns = vulns_res.scalars().all()
        seen_vulns: Set[Tuple[Optional[int], str, Optional[int]]] = set()
        duplicate_vuln_ids: List[int] = []

        for v in vulns:
            v_key = (v.affected_asset_id, v.cve_id, v.port_affected)
            if v_key in seen_vulns:
                duplicate_vuln_ids.append(v.id)
                report["vulns_deduplicated"] += 1
                continue
            seen_vulns.add(v_key)

            # G. Normalize timestamp
            if v.discovered_at:
                norm_ts = cls.normalize_timestamp(v.discovered_at)
                if norm_ts:
                    v.discovered_at = norm_ts
                    report["timestamps_normalized"] += 1

        if duplicate_vuln_ids:
            await db.execute(delete(Vulnerability).where(Vulnerability.id.in_(duplicate_vuln_ids)))

        await db.commit()
        return report
