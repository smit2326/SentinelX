import asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.database import Base, engine, AsyncSessionLocal
from app.core.security import get_password_hash
from app.models.user import User, UserRole
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnSeverity, VulnStatus
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.audit_log import AuditLog
from app.models.system_config import SystemConfig
from app.services.risk_engine import calculate_asset_risk
from app.core.logger import logger

async def init_and_seed_db():
    logger.info("Initializing database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as db:
        # Check if already seeded
        user_check = await db.execute(select(User))
        if user_check.scalars().first():
            logger.info("Database already seeded with foundation data.")
            return

        logger.info("Seeding SENTINEL-X Foundation dataset...")
        
        # 1. Seed Users (Admin, Analyst, Auditor)
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

        # 2. Seed Assets
        now = datetime.now(timezone.utc)
        assets = [
            Asset(
                ip_address="192.168.1.1",
                mac_address="52:54:00:12:34:01",
                hostname="edge-fw-pfsense.gw.lan",
                device_type="Firewall",
                vendor="Netgate",
                os_name="FreeBSD",
                os_version="14.0-RELEASE",
                open_ports=[
                    {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 9.3"},
                    {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "pfSense WebGUI"}
                ],
                services=[{"name": "pfsense", "version": "2.7.2"}],
                is_iot=False,
                is_cctv=False,
                risk_score=15.0,
                status="Online",
                location="Primary Gateway Rack 01",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.10",
                mac_address="52:54:00:88:99:10",
                hostname="win-dc-ad01.corp.sentinel.sec",
                device_type="Server",
                vendor="Microsoft Corporation",
                os_name="Windows Server",
                os_version="2022 Datacenter",
                open_ports=[
                    {"port": 53, "protocol": "udp", "service": "dns", "state": "open", "version": "Microsoft DNS"},
                    {"port": 88, "protocol": "tcp", "service": "kerberos", "state": "open", "version": "Active Directory Kerberos"},
                    {"port": 389, "protocol": "tcp", "service": "ldap", "state": "open", "version": "Microsoft LDAP"},
                    {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open", "version": "SMBv3"},
                    {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "state": "open", "version": "Microsoft RDP"}
                ],
                services=[{"name": "active_directory", "version": "2022"}, {"name": "smb", "version": "3.1.1"}],
                is_iot=False,
                is_cctv=False,
                risk_score=85.0,
                status="Warning",
                location="HQ Datacenter Row A",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.20",
                mac_address="52:54:00:aa:bb:20",
                hostname="k8s-ingress-lb01.prod.sentinel.sec",
                device_type="Server",
                vendor="Dell EMC",
                os_name="Ubuntu Linux",
                os_version="22.04 LTS",
                open_ports=[
                    {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 8.9p1"},
                    {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "nginx/1.24.0"},
                    {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "nginx/1.24.0"},
                    {"port": 6443, "protocol": "tcp", "service": "kube-apiserver", "state": "open", "version": "Kubernetes v1.28.3"}
                ],
                services=[{"name": "nginx", "version": "1.24.0"}, {"name": "kubernetes", "version": "1.28.3"}],
                is_iot=False,
                is_cctv=False,
                risk_score=68.0,
                status="Online",
                location="HQ Datacenter Row B",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.25",
                mac_address="52:54:00:cc:dd:25",
                hostname="db-cluster-pg01.prod.sentinel.sec",
                device_type="Server",
                vendor="HPE ProLiant",
                os_name="Debian GNU/Linux",
                os_version="12 (Bookworm)",
                open_ports=[
                    {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 9.2p1"},
                    {"port": 5432, "protocol": "tcp", "service": "postgresql", "state": "open", "version": "PostgreSQL 16.1"}
                ],
                services=[{"name": "postgresql", "version": "16.1"}],
                is_iot=False,
                is_cctv=False,
                risk_score=22.0,
                status="Online",
                location="HQ Datacenter Row B",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.45",
                mac_address="00:12:12:44:55:66",
                hostname="cctv-cam-perimeter-north.sec.lan",
                device_type="CCTV Camera",
                vendor="Hikvision Digital",
                os_name="Embedded Linux",
                os_version="V5.5.80 build 210628",
                open_ports=[
                    {"port": 80, "protocol": "tcp", "service": "http-alt", "state": "open", "version": "GoAhead-Webs 2.5"},
                    {"port": 554, "protocol": "tcp", "service": "rtsp", "state": "open", "version": "Hikvision RTSP Server 1.0"},
                    {"port": 8000, "protocol": "tcp", "service": "dvr-mgmt", "state": "open", "version": "DVR Admin 2.1"}
                ],
                services=[{"name": "rtsp", "version": "1.0"}, {"name": "onvif", "version": "2.4"}],
                is_iot=True,
                is_cctv=True,
                firmware_version="v1.4.2-unpatched",
                cctv_stream_protocol="RTSP (H.264 / 1080p)",
                risk_score=94.0,
                status="Quarantined",
                is_quarantined=True,
                location="Perimeter Fence Pole 03",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.46",
                mac_address="00:1a:2b:77:88:99",
                hostname="cctv-cam-dc-vault.sec.lan",
                device_type="CCTV Camera",
                vendor="Dahua Technology",
                os_name="Embedded Linux",
                os_version="V4.000.0000000.1.R",
                open_ports=[
                    {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "Embedded Web"},
                    {"port": 554, "protocol": "tcp", "service": "rtsp", "state": "open", "version": "Dahua RTSP Streamer 2.0"},
                    {"port": 37777, "protocol": "tcp", "service": "dahua-mgmt", "state": "open", "version": "Dahua RPC"}
                ],
                services=[{"name": "rtsp", "version": "2.0"}, {"name": "onvif", "version": "3.0"}],
                is_iot=True,
                is_cctv=True,
                firmware_version="v2.8.0-signed",
                cctv_stream_protocol="RTSP (H.265 / 4K)",
                risk_score=45.0,
                status="Online",
                location="Datacenter Vault Access Door",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.72",
                mac_address="70:b3:d5:11:22:33",
                hostname="bms-hvac-controller-b2.corp.lan",
                device_type="IoT Device",
                vendor="Schneider Electric",
                os_name="FreeRTOS",
                os_version="v10.4.3",
                open_ports=[
                    {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "Embedded HTTPd"},
                    {"port": 502, "protocol": "tcp", "service": "modbus", "state": "open", "version": "Modbus TCP Gateway"}
                ],
                services=[{"name": "modbus-tcp", "version": "1.0"}],
                is_iot=True,
                is_cctv=False,
                firmware_version="v2.1.0-sec",
                risk_score=62.0,
                status="Online",
                location="Building 2 Mechanical Room",
                subnet="192.168.1.0/24"
            ),
            Asset(
                ip_address="192.168.1.150",
                mac_address="52:54:00:ef:12:50",
                hostname="secops-ws-04.corp.lan",
                device_type="Workstation",
                vendor="Lenovo ThinkStation",
                os_name="Windows 11 Enterprise",
                os_version="23H2",
                open_ports=[
                    {"port": 135, "protocol": "tcp", "service": "msrpc", "state": "open", "version": "Microsoft RPC"},
                    {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open", "version": "SMBv3"}
                ],
                services=[{"name": "smb", "version": "3.1.1"}],
                is_iot=False,
                is_cctv=False,
                risk_score=35.0,
                status="Online",
                location="SOC Level 3 Bullpen",
                subnet="192.168.1.0/24"
            )
        ]
        db.add_all(assets)
        await db.flush()

        # 3. Seed Vulnerabilities linked to assets
        vulns = [
            Vulnerability(
                cve_id="CVE-2021-36260",
                title="Hikvision IP Camera Command Injection Vulnerability",
                description="A command injection vulnerability in the web server of some Hikvision IP cameras allows an attacker to send specially crafted messages to vulnerable devices for root shell access.",
                cvss_score=9.8,
                severity=VulnSeverity.CRITICAL.value,
                affected_asset_id=assets[4].id, # CCTV Cam 01
                affected_service="GoAhead-Webs 2.5 (Port 80)",
                port_affected=80,
                remediation="Upgrade camera firmware to v5.5.800 build 210901 or higher immediately and isolate RTSP subnet.",
                status=VulnStatus.OPEN.value,
                exploit_available="Weaponized"
            ),
            Vulnerability(
                cve_id="CVE-2020-1472",
                title="Zerologon (Netlogon Elevation of Privilege)",
                description="An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller using MS-NRPC.",
                cvss_score=10.0,
                severity=VulnSeverity.CRITICAL.value,
                affected_asset_id=assets[1].id, # Windows DC
                affected_service="Active Directory Netlogon (Port 445)",
                port_affected=445,
                remediation="Apply Microsoft Security Update KB4565349 and enforce secure RPC communications.",
                status=VulnStatus.INVESTIGATING.value,
                exploit_available="Weaponized"
            ),
            Vulnerability(
                cve_id="CVE-2024-3094",
                title="XZ Utils Upstream Backdoor Injection",
                description="Malicious code was discovered in upstream tarballs of xz format compression beginning with version 5.6.0 that can allow unauthorized SSH authentication bypass.",
                cvss_score=10.0,
                severity=VulnSeverity.CRITICAL.value,
                affected_asset_id=assets[2].id, # K8s Ingress
                affected_service="OpenSSH 8.9p1 (liblzma dependency)",
                port_affected=22,
                remediation="Downgrade or verify liblzma package version is >= 5.6.2 or <= 5.4.x.",
                status=VulnStatus.MITIGATED.value,
                exploit_available="POC",
                resolved_at=now - timedelta(hours=12)
            ),
            Vulnerability(
                cve_id="CVE-2022-30525",
                title="Zyxel / Firewall Unauthenticated Remote Command Execution",
                description="An unauthenticated remote code execution vulnerability in the CGI component of multiple firewall series allows execution of arbitrary OS commands.",
                cvss_score=9.8,
                severity=VulnSeverity.CRITICAL.value,
                affected_asset_id=assets[0].id,
                affected_service="WebGUI CGI",
                port_affected=443,
                remediation="Restrict administrative access to management VLAN and update firmware.",
                status=VulnStatus.MITIGATED.value,
                exploit_available="POC",
                resolved_at=now - timedelta(days=2)
            ),
            Vulnerability(
                cve_id="CVE-2022-26134",
                title="Atlassian Confluence OGNL Injection Remote Code Execution",
                description="In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that allows unauthenticated command execution.",
                cvss_score=9.8,
                severity=VulnSeverity.CRITICAL.value,
                affected_asset_id=assets[2].id,
                affected_service="Internal Wiki (Port 8080)",
                port_affected=8080,
                remediation="Upgrade Confluence Server to latest LTS release.",
                status=VulnStatus.OPEN.value,
                exploit_available="Weaponized"
            ),
            Vulnerability(
                cve_id="CVE-2023-4911",
                title="Looney Tunables - Glibc ld.so Buffer Overflow",
                description="A buffer overflow vulnerability in GNU C Library dynamic loader ld.so when processing the GLIBC_TUNABLES environment variable.",
                cvss_score=7.8,
                severity=VulnSeverity.HIGH.value,
                affected_asset_id=assets[3].id, # Postgres
                affected_service="Local OS Shell",
                port_affected=22,
                remediation="Run 'apt-get upgrade libc6' to install patched upstream glibc.",
                status=VulnStatus.OPEN.value,
                exploit_available="POC"
            )
        ]
        db.add_all(vulns)
        await db.flush()

        # 4. Seed Alerts
        alerts = [
            Alert(
                title="CCTV Unauthenticated RTSP Feed Stream Hijack Attempt",
                category="CCTV / IoT Security",
                severity=AlertSeverity.CRITICAL.value,
                source_ip="185.220.101.5",
                destination_ip="192.168.1.45",
                protocol="RTSP",
                affected_asset_id=assets[4].id,
                description="External IP attempted unauthorized RTSP SETUP/DESCRIBE session without valid digest authentication.",
                raw_packet_hex="53 45 54 55 50 20 72 74 73 70 3a 2f 2f 31 39 32 2e 31 36 38 2e 31 2e 34 35 2f 6c 69 76 65 2e 73 64 70",
                metadata_json={"camera_model": "DS-2CD2043G0-I", "stream_uri": "/live.sdp", "attempts": 14},
                status=AlertStatus.ACTIVE.value,
                created_at=now - timedelta(minutes=14)
            ),
            Alert(
                title="Active Directory Kerberoasting Ticket Request Spike",
                category="Lateral Movement",
                severity=AlertSeverity.CRITICAL.value,
                source_ip="192.168.1.150",
                destination_ip="192.168.1.10",
                protocol="Kerberos",
                affected_asset_id=assets[1].id,
                description="Abnormal burst of TGS requests with RC4-HMAC encryption targeting MSSQLSvc and HTTP SPN accounts.",
                raw_packet_hex="6a 81 b5 30 81 b2 a0 03 02 01 05 a1 03 02 01 0c a2 07 03 05 00 20",
                metadata_json={"spn_targets": ["MSSQLSvc/db01.corp", "HTTP/web-portal"], "tgs_count": 48},
                status=AlertStatus.INVESTIGATING.value,
                assigned_to="Sarah Chen (Lead SOC Analyst)",
                created_at=now - timedelta(minutes=45)
            ),
            Alert(
                title="Industrial Modbus Protocol Register Overwrite Attempt",
                category="Industrial IoT Anomaly",
                severity=AlertSeverity.HIGH.value,
                source_ip="192.168.1.99",
                destination_ip="192.168.1.72",
                protocol="MODBUS-TCP",
                affected_asset_id=assets[6].id,
                description="Modbus function code 0x10 (Write Multiple Registers) detected trying to modify HVAC chiller temp thresholds.",
                raw_packet_hex="00 01 00 00 00 09 01 10 00 01 00 01 02 00 64",
                metadata_json={"register_address": "40001", "written_value": "100 (Max Capacity)"},
                status=AlertStatus.ACTIVE.value,
                created_at=now - timedelta(hours=1, minutes=20)
            ),
            Alert(
                title="TCP SYN Scan Sweeping Core Subnet",
                category="Traffic Monitoring",
                severity=AlertSeverity.MEDIUM.value,
                source_ip="198.51.100.42",
                destination_ip="192.168.1.1",
                protocol="TCP",
                affected_asset_id=assets[0].id,
                description="Sequential port scan detected probing ports 1-1024 at rate > 1,200 pkt/s.",
                raw_packet_hex="45 00 00 3c 1a 2b 40 00 40 06 b2 a1 c6 33 64 2a c0 a8 01 01 00 16",
                metadata_json={"flags": "SYN", "packet_rate": "1240 pps"},
                status=AlertStatus.RESOLVED.value,
                created_at=now - timedelta(hours=4),
                resolved_at=now - timedelta(hours=3)
            )
        ]
        db.add_all(alerts)
        await db.flush()

        # 5. Seed System Configs
        configs = [
            SystemConfig(key="scanner.default_subnet", value="192.168.1.0/24", category="scanner", description="Primary CIDR range for network asset discovery probes"),
            SystemConfig(key="scanner.rate_limit_pps", value="1000", category="scanner", description="Maximum packets per second for Nmap/Scapy discovery engines"),
            SystemConfig(key="scanner.nmap_timing_template", value="T4", category="scanner", description="Nmap timing aggression (T1 sneaky to T5 insane)"),
            SystemConfig(key="scanner.cctv_rtsp_deep_scan", value="true", category="scanner", description="Enable active RTSP/ONVIF port banner and auth probing"),
            SystemConfig(key="siem.webhook_url", value="https://siem.corp.sentinel.sec/hooks/aegis-alerts", category="notification", description="External SIEM / Webhook target for critical incident dispatch"),
            SystemConfig(key="siem.slack_alert_channel", value="#soc-critical-alerts", category="notification", description="Slack / Discord channel webhook for immediate analyst notification"),
            SystemConfig(key="threat_intel.nvd_api_key", value="cve-api-key-live-sentinel-2026-prod", category="threat_intel", description="National Vulnerability Database (NVD) v2 API key", is_secret=True),
            SystemConfig(key="threat_intel.auto_correlate", value="true", category="threat_intel", description="Automatically correlate newly discovered service banners with open CVE feeds"),
            SystemConfig(key="simulation.background_traffic", value="true", category="traffic_capture", description="Simulate live network packets and periodic incident beacons")
        ]
        db.add_all(configs)
        await db.flush()

        # 6. Seed Initial Audit Logs
        audit_records = [
            AuditLog(
                actor_id=users[0].id,
                actor_email=users[0].email,
                actor_role=users[0].role,
                action="SYSTEM_INITIALIZED",
                resource="system",
                resource_id="0",
                status="SUCCESS",
                ip_address="127.0.0.1",
                details={"platform": "SENTINEL-X", "phase": "Phase 1 Foundation", "version": "1.0.0"}
            ),
            AuditLog(
                actor_id=users[1].id,
                actor_email=users[1].email,
                actor_role=users[1].role,
                action="ASSET_QUARANTINED",
                resource="assets",
                resource_id=str(assets[4].id),
                status="SUCCESS",
                ip_address="192.168.1.150",
                details={"ip": assets[4].ip_address, "reason": "CVE-2021-36260 exploit attempt observed"}
            )
        ]
        db.add_all(audit_records)
        await db.commit()
        
        logger.info("SENTINEL-X database successfully seeded with all initial entities!")

if __name__ == "__main__":
    asyncio.run(init_and_seed_db())
