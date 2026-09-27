"""
OpenVAS / Greenbone Vulnerability Management Service.
Handles OpenVAS report parsing (XML/CSV), remote connection testing,
and database ingestion into Sentinel-X assets and vulnerability registries.
"""

import csv
import io
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.logger import logger
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnSeverity, VulnStatus
from app.models.alert import Alert
from app.services.risk_engine import calculate_asset_risk
from app.services.websocket_manager import ws_manager
from app.services.audit_service import log_audit_event

# Default OpenVAS configuration state
openvas_config: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 9390,
    "username": "admin",
    "use_tls": True,
    "last_connection_test": None,
    "last_connection_status": "NOT_CONNECTED",
    "imported_reports_count": 0,
    "total_vulns_ingested": 0
}


def get_openvas_status() -> Dict[str, Any]:
    """Returns the current OpenVAS connector configuration and telemetry."""
    return {
        "configured": bool(openvas_config.get("host")),
        "host": openvas_config["host"],
        "port": openvas_config["port"],
        "username": openvas_config["username"],
        "use_tls": openvas_config["use_tls"],
        "last_connection_test": openvas_config["last_connection_test"],
        "last_connection_status": openvas_config["last_connection_status"],
        "imported_reports_count": openvas_config["imported_reports_count"],
        "total_vulns_ingested": openvas_config["total_vulns_ingested"],
        "supported_formats": ["OpenVAS XML (*.xml)", "OpenVAS CSV (*.csv)"]
    }


def update_openvas_config(host: str, port: int, username: str, use_tls: bool = True) -> Dict[str, Any]:
    """Updates OpenVAS connection settings."""
    openvas_config["host"] = host.strip()
    openvas_config["port"] = int(port)
    openvas_config["username"] = username.strip()
    openvas_config["use_tls"] = use_tls
    openvas_config["last_connection_status"] = "PENDING_TEST"
    return get_openvas_status()


def test_openvas_connection() -> Dict[str, Any]:
    """
    Tests TCP connectivity to the configured OpenVAS / Greenbone GMP daemon port.
    Returns status and diagnostic guidance.
    """
    host = openvas_config["host"]
    port = openvas_config["port"]
    timestamp = datetime.now(timezone.utc).isoformat()
    openvas_config["last_connection_test"] = timestamp

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        res = sock.connect_ex((host, port))
        sock.close()

        if res == 0:
            openvas_config["last_connection_status"] = "CONNECTED"
            return {
                "success": True,
                "status": "CONNECTED",
                "message": f"Successfully connected to OpenVAS daemon at {host}:{port}.",
                "timestamp": timestamp
            }

        openvas_config["last_connection_status"] = "PORT_UNREACHABLE"
        return {
            "success": False,
            "status": "PORT_UNREACHABLE",
            "message": (
                f"Could not connect to OpenVAS daemon at {host}:{port}. "
                "Ensure Greenbone/OpenVAS is running (e.g. inside Docker or remote Linux server) "
                "or use Report Ingestion mode to import XML/CSV reports."
            ),
            "timestamp": timestamp
        }
    except Exception as exc: # pylint: disable=broad-exception-caught
        openvas_config["last_connection_status"] = "CONNECTION_ERROR"
        return {
            "success": False,
            "status": "CONNECTION_ERROR",
            "message": f"Connection check failed: {str(exc)}",
            "timestamp": timestamp
        }


def parse_openvas_xml(xml_content: str) -> List[Dict[str, Any]]:
    """
    Parses OpenVAS / Greenbone XML report format into structured vulnerability findings.
    Handles standard OpenVAS <report> -> <results> -> <result> hierarchy.
    """
    findings: List[Dict[str, Any]] = []
    root = ET.fromstring(xml_content)

    # Locate all <result> tags across the XML document
    results = root.findall(".//result")
    for r in results:
        # Extract host & port
        host_el = r.find("host")
        host_ip = host_el.text.strip() if host_el is not None and host_el.text else "127.0.0.1"

        port_raw = "0"
        port_el = r.find("port")
        if port_el is not None and port_el.text:
            port_raw = port_el.text.strip().split("/")[0]
        try:
            port_num = int(port_raw) if port_raw.isdigit() else None
        except ValueError:
            port_num = None

        # NVT (Network Vulnerability Test) details
        nvt = r.find("nvt")
        title = "OpenVAS Security Finding"
        cve_ids = []
        cvss_score = 5.0
        solution = "Review vendor advisory and apply the recommended software update."

        if nvt is not None:
            name_el = nvt.find("name")
            if name_el is not None and name_el.text:
                title = name_el.text.strip()

            cve_el = nvt.find("cve")
            if cve_el is not None and cve_el.text and cve_el.text != "NOCVE":
                cve_ids = [c.strip() for c in cve_el.text.split(",") if c.strip().startswith("CVE-")]

            cvss_el = nvt.find("cvss_base")
            if cvss_el is not None and cvss_el.text:
                try:
                    cvss_score = float(cvss_el.text.strip())
                except ValueError:
                    pass

            sol_el = nvt.find("solution")
            if sol_el is not None and sol_el.text:
                solution = sol_el.text.strip()

        # Description / Summary
        desc_el = r.find("description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else title

        # Threat severity calculation
        threat_el = r.find("threat")
        severity_str = threat_el.text.strip().upper() if threat_el is not None and threat_el.text else ""
        if not severity_str:
            if cvss_score >= 9.0:
                severity_str = "CRITICAL"
            elif cvss_score >= 7.0:
                severity_str = "HIGH"
            elif cvss_score >= 4.0:
                severity_str = "MEDIUM"
            elif cvss_score > 0.0:
                severity_str = "LOW"
            else:
                severity_str = "INFO"

        if severity_str in ["LOG", "DEBUG", "NONE"]:
            continue  # Skip informational logs without security impact

        # Determine primary CVE or fallback to OpenVAS reference
        primary_cve = cve_ids[0] if cve_ids else f"OPENVAS-{abs(hash(title)) % 100000:05d}"

        findings.append({
            "ip_address": host_ip,
            "port": port_num,
            "cve_id": primary_cve,
            "all_cves": cve_ids,
            "title": title,
            "description": description,
            "cvss_score": min(cvss_score, 10.0),
            "severity": severity_str,
            "solution": solution,
            "detection_source": "OpenVAS / Greenbone Vulnerability Scanner"
        })

    return findings


def parse_openvas_csv(csv_content: str) -> List[Dict[str, Any]]:
    """
    Parses OpenVAS / Greenbone CSV report exports.
    Matches standard column names and extracts vulnerability items.
    """
    findings: List[Dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(csv_content))

    for row in reader:
        # Standardize keys (strip whitespace, lowercase)
        norm_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}

        host_ip = norm_row.get("ip") or norm_row.get("host") or "127.0.0.1"
        port_raw = norm_row.get("port") or norm_row.get("service") or "0"
        port_clean = port_raw.split("/")[0]
        port_num = int(port_clean) if port_clean.isdigit() else None

        title = norm_row.get("nvt name") or norm_row.get("name") or norm_row.get("vulnerability") or "OpenVAS Finding"
        desc = norm_row.get("summary") or norm_row.get("description") or title
        solution = norm_row.get("solution") or "Apply latest vendor security patch."

        # Parse CVSS score
        cvss_raw = norm_row.get("cvss") or norm_row.get("score") or "5.0"
        try:
            cvss_score = float(cvss_raw)
        except ValueError:
            cvss_score = 5.0

        # Parse severity
        severity = norm_row.get("severity") or norm_row.get("threat") or ""
        severity = severity.upper()
        if not severity:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            elif cvss_score > 0.0:
                severity = "LOW"
            else:
                severity = "INFO"

        if severity in ["LOG", "DEBUG", "NONE"]:
            continue

        cves_raw = norm_row.get("cves") or norm_row.get("cve") or ""
        cve_list = [c.strip() for c in cves_raw.split(",") if c.strip().startswith("CVE-")]
        primary_cve = cve_list[0] if cve_list else f"OPENVAS-{abs(hash(title)) % 100000:05d}"

        findings.append({
            "ip_address": host_ip,
            "port": port_num,
            "cve_id": primary_cve,
            "all_cves": cve_list,
            "title": title,
            "description": desc,
            "cvss_score": min(cvss_score, 10.0),
            "severity": severity,
            "solution": solution,
            "detection_source": "OpenVAS / Greenbone CSV Report"
        })

    return findings


async def ingest_openvas_findings(
    db: AsyncSession,
    findings: List[Dict[str, Any]],
    actor_email: str
) -> Dict[str, Any]:
    """
    Ingests parsed OpenVAS findings into the Sentinel-X database.
    - Creates or updates target assets.
    - Links new vulnerabilities with CVSS scores and remediation steps.
    - Recalculates risk scores using risk_engine.
    """
    if not findings:
        return {
            "success": True,
            "imported_count": 0,
            "assets_affected": 0,
            "message": "No actionable security findings found in report."
        }

    affected_assets: Dict[str, Asset] = {}
    new_vuln_count = 0
    updated_vuln_count = 0

    for f in findings:
        ip = f["ip_address"]
        # Find or create asset
        if ip not in affected_assets:
            stmt = select(Asset).where(Asset.ip_address == ip)
            res = await db.execute(stmt)
            asset = res.scalars().first()
            if not asset:
                # Infer device type based on port/CVE
                dev_type = "Workstation"
                if f.get("port") == 554 or "camera" in f["title"].lower() or "rtsp" in f["title"].lower():
                    dev_type = "CCTV Camera"
                elif f.get("port") in [80, 443, 8080] and ("router" in f["title"].lower() or "gateway" in f["title"].lower()):
                    dev_type = "Router"
                elif f.get("port") in [135, 445, 3389, 5432]:
                    dev_type = "Server"

                asset = Asset(
                    ip_address=ip,
                    hostname=f"Host-{ip.replace('.', '-')}",
                    device_type=dev_type,
                    vendor="OpenVAS Discovered",
                    os_name="Network Host",
                    open_ports=[{"port": f["port"], "service": "openvas-scanned", "state": "open"}] if f["port"] else [],
                    status="Warning" if f["cvss_score"] >= 7.0 else "Online",
                    is_cctv=(dev_type == "CCTV Camera"),
                    last_scanned=datetime.now(timezone.utc)
                )
                db.add(asset)
                await db.flush()
            affected_assets[ip] = asset

        target_asset = affected_assets[ip]

        # Check if vulnerability already registered for this asset
        cve_id = f["cve_id"]
        vuln_stmt = select(Vulnerability).where(
            Vulnerability.affected_asset_id == target_asset.id,
            Vulnerability.cve_id == cve_id
        )
        vuln_res = await db.execute(vuln_stmt)
        existing_vuln = vuln_res.scalars().first()

        sev_value = f["severity"]
        if sev_value not in [s.value for s in VulnSeverity]:
            sev_value = VulnSeverity.MEDIUM.value

        if existing_vuln:
            existing_vuln.cvss_score = f["cvss_score"]
            existing_vuln.severity = sev_value
            existing_vuln.remediation = f["solution"]
            updated_vuln_count += 1
        else:
            new_vuln = Vulnerability(
                cve_id=cve_id,
                title=f["title"],
                description=f["description"],
                cvss_score=f["cvss_score"],
                severity=sev_value,
                affected_asset_id=target_asset.id,
                affected_service=f"Port {f['port']}" if f["port"] else "System",
                port_affected=f["port"],
                remediation=f["solution"],
                exploit_available="POC" if f["cvss_score"] >= 8.0 else "No",
                status=VulnStatus.OPEN.value
            )
            db.add(new_vuln)
            new_vuln_count += 1

    # Recalculate risk score for each affected asset
    for asset in affected_assets.values():
        vulns_res = await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset.id))
        asset_vulns = vulns_res.scalars().all()
        alerts_res = await db.execute(select(Alert).where(Alert.affected_asset_id == asset.id))
        asset_alerts = alerts_res.scalars().all()

        asset.risk_score = calculate_asset_risk(asset, asset_vulns, asset_alerts)
        if asset.risk_score >= 70.0:
            asset.status = "Warning"

    await db.commit()

    openvas_config["imported_reports_count"] += 1
    openvas_config["total_vulns_ingested"] += (new_vuln_count + updated_vuln_count)

    await log_audit_event(
        db=db,
        action="OPENVAS_REPORT_INGESTED",
        resource="vulnerabilities",
        actor_email=actor_email,
        details={
            "new_vulnerabilities": new_vuln_count,
            "updated_vulnerabilities": updated_vuln_count,
            "assets_affected": len(affected_assets)
        }
    )

    await ws_manager.broadcast_scan_update(
        progress=100,
        status="OPENVAS_INGESTION_COMPLETED",
        details={
            "new_vulns": new_vuln_count,
            "assets_count": len(affected_assets),
            "message": f"OpenVAS ingestion completed: {new_vuln_count} new CVEs mapped to {len(affected_assets)} asset(s)."
        }
    )

    return {
        "success": True,
        "new_vulnerabilities": new_vuln_count,
        "updated_vulnerabilities": updated_vuln_count,
        "assets_affected": len(affected_assets),
        "message": f"Successfully ingested {new_vuln_count + updated_vuln_count} findings across {len(affected_assets)} assets."
    }


def generate_sample_openvas_xml() -> str:
    """
    Generates a realistic OpenVAS XML report containing genuine CVE assessments
    for a Router, CCTV Camera, and Network Server to test Phase 2 assessment.
    """
    return """<?xml version="1.0" encoding="UTF-8"?>
<report id="openvas-rep-001" format_id="5057e5cc-b825-11e4-9d0e-28d24461215b">
  <report id="openvas-rep-001">
    <scan_run_status>Done</scan_run_status>
    <results>
      <!-- Finding 1: Router Remote Command Injection -->
      <result id="res-001">
        <name>TP-Link Archer / Router Web Management Unauthenticated Command Injection</name>
        <host>192.168.1.1</host>
        <port>80/tcp</port>
        <threat>High</threat>
        <severity>8.8</severity>
        <description>The remote router contains a command injection flaw in its web administration interface. An unauthenticated attacker on the local network can execute arbitrary commands via crafted HTTP requests.</description>
        <nvt oid="1.3.6.1.4.1.25623.1.0.149542">
          <name>TP-Link Archer Command Injection (CVE-2023-1389)</name>
          <cve>CVE-2023-1389</cve>
          <cvss_base>8.8</cvss_base>
          <solution type="VendorFix">Upgrade router firmware to latest vendor release or disable remote web management.</solution>
        </nvt>
      </result>

      <!-- Finding 2: CCTV Camera Remote Code Execution -->
      <result id="res-002">
        <name>Hikvision IP Camera Unauthenticated Remote Code Execution</name>
        <host>192.168.1.65</host>
        <port>554/tcp</port>
        <threat>Critical</threat>
        <severity>9.8</severity>
        <description>A critical command injection vulnerability exists in the web server of multiple IP camera models. By sending crafted messages to the affected device, an attacker can obtain root command shell access.</description>
        <nvt oid="1.3.6.1.4.1.25623.1.0.146741">
          <name>Hikvision IP Camera Backdoor / Command Injection (CVE-2021-36260)</name>
          <cve>CVE-2021-36260</cve>
          <cvss_base>9.8</cvss_base>
          <solution type="VendorFix">Apply firmware patch version V5.5.800 or newer immediately and isolate surveillance VLAN.</solution>
        </nvt>
      </result>

      <!-- Finding 3: Linux Network Server SSH Weak Cipher Exposure -->
      <result id="res-003">
        <name>OpenSSH CBC Mode Cipher Insecurity &amp; PKCS#11 Provider Vulnerability</name>
        <host>192.168.1.200</host>
        <port>22/tcp</port>
        <threat>High</threat>
        <severity>7.8</severity>
        <description>The remote SSH daemon supports legacy CBC ciphers and an outdated OpenSSH release vulnerable to arbitrary PKCS#11 provider library loading.</description>
        <nvt oid="1.3.6.1.4.1.25623.1.0.108422">
          <name>OpenSSH PKCS#11 Remote Code Execution (CVE-2023-38408)</name>
          <cve>CVE-2023-38408</cve>
          <cvss_base>7.8</cvss_base>
          <solution type="Workaround">Update OpenSSH to version 9.3p2 or later and restrict Ciphers in sshd_config to chacha20-poly1305 and aes-gcm.</solution>
        </nvt>
      </result>
    </results>
  </report>
</report>
"""
