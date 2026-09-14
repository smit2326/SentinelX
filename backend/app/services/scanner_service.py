import asyncio
import random
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.alert import Alert
from app.services.risk_engine import calculate_asset_risk
from app.services.websocket_manager import ws_manager
from app.services.audit_service import log_audit_event
from app.core.logger import logger

DISCOVERY_TEMPLATES = [
    {
        "ip_offset": 10,
        "hostname": "k8s-node-worker-01.prod.lan",
        "device_type": "Server",
        "vendor": "Dell EMC",
        "os_name": "Ubuntu Linux",
        "os_version": "22.04 LTS (Jammy)",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 8.9p1"},
            {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "nginx/1.24.0"},
            {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "nginx/1.24.0"},
            {"port": 6443, "protocol": "tcp", "service": "kube-apiserver", "state": "open", "version": "Kubernetes v1.28"}
        ],
        "services": [{"name": "nginx", "version": "1.24.0"}, {"name": "kubelet", "version": "1.28.3"}],
        "is_iot": False,
        "is_cctv": False
    },
    {
        "ip_offset": 45,
        "hostname": "cctv-cam-perimeter-north.sec.lan",
        "device_type": "CCTV Camera",
        "vendor": "Hikvision Digital",
        "os_name": "Embedded Linux",
        "os_version": "V5.5.80",
        "open_ports": [
            {"port": 80, "protocol": "tcp", "service": "http-alt", "state": "open", "version": "GoAhead-Webs"},
            {"port": 554, "protocol": "tcp", "service": "rtsp", "state": "open", "version": "Hikvision RTSP Server"},
            {"port": 8000, "protocol": "tcp", "service": "dvr-mgmt", "state": "open", "version": "DVR Admin 2.1"}
        ],
        "services": [{"name": "rtsp", "version": "1.0"}, {"name": "onvif", "version": "2.4"}],
        "is_iot": True,
        "is_cctv": True,
        "firmware_version": "v1.4.2-unpatched",
        "cctv_stream_protocol": "RTSP (H.264)"
    },
    {
        "ip_offset": 72,
        "hostname": "bms-hvac-controller-b2.corp.lan",
        "device_type": "IoT Device",
        "vendor": "Schneider Electric",
        "os_name": "FreeRTOS",
        "os_version": "v10.4.3",
        "open_ports": [
            {"port": 80, "protocol": "tcp", "service": "http", "state": "open", "version": "Embedded HTTPd"},
            {"port": 502, "protocol": "tcp", "service": "modbus", "state": "open", "version": "Modbus TCP Gateway"}
        ],
        "services": [{"name": "modbus-tcp", "version": "1.0"}],
        "is_iot": True,
        "is_cctv": False,
        "firmware_version": "v2.1.0-sec"
    },
    {
        "ip_offset": 105,
        "hostname": "win-dc-ad01.corp.contoso.com",
        "device_type": "Server",
        "vendor": "Microsoft Corporation",
        "os_name": "Windows Server",
        "os_version": "2022 Datacenter",
        "open_ports": [
            {"port": 53, "protocol": "udp", "service": "dns", "state": "open", "version": "Microsoft DNS"},
            {"port": 88, "protocol": "tcp", "service": "kerberos", "state": "open", "version": "Microsoft Kerberos"},
            {"port": 389, "protocol": "tcp", "service": "ldap", "state": "open", "version": "Active Directory LDAP"},
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open", "version": "SMBv2/v3"},
            {"port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "state": "open", "version": "Microsoft RDP"}
        ],
        "services": [{"name": "active_directory", "version": "2022"}, {"name": "smb", "version": "3.1.1"}],
        "is_iot": False,
        "is_cctv": False
    },
    {
        "ip_offset": 1,
        "hostname": "edge-fw-pfsense.gw.lan",
        "device_type": "Firewall",
        "vendor": "Netgate",
        "os_name": "FreeBSD",
        "os_version": "14.0-RELEASE",
        "open_ports": [
            {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open", "version": "OpenSSH 9.3"},
            {"port": 443, "protocol": "tcp", "service": "https", "state": "open", "version": "pfSense WebGUI"}
        ],
        "services": [{"name": "pfsense", "version": "2.7.2"}],
        "is_iot": False,
        "is_cctv": False
    }
]

async def execute_network_discovery(
    db: AsyncSession,
    target_subnet: str,
    scan_type: str,
    actor_email: str
) -> Dict[str, Any]:
    logger.info(f"Initiating network scan on subnet {target_subnet} (Type: {scan_type}) by {actor_email}")
    
    # Broadcast start
    await ws_manager.broadcast_scan_update(
        progress=10,
        status="ARP_PING_SWEEP",
        details={"subnet": target_subnet, "message": f"Broadcasting ICMP/ARP probes across {target_subnet}"}
    )
    await asyncio.sleep(0.8)
    
    await ws_manager.broadcast_scan_update(
        progress=40,
        status="PORT_FINGERPRINTING",
        details={"subnet": target_subnet, "message": "Probing TCP/UDP service banners and SSL certificates..."}
    )
    await asyncio.sleep(0.8)
    
    await ws_manager.broadcast_scan_update(
        progress=75,
        status="CCTV_IOT_HEURISTICS",
        details={"subnet": target_subnet, "message": "Analyzing RTSP / ONVIF streams & embedded firmware..."}
    )
    await asyncio.sleep(0.8)

    # Process templates & update/create assets
    base_prefix = target_subnet.rsplit(".", 1)[0]
    discovered_count = 0
    
    for t in DISCOVERY_TEMPLATES:
        ip = f"{base_prefix}.{t['ip_offset']}"
        stmt = select(Asset).where(Asset.ip_address == ip)
        result = await db.execute(stmt)
        asset = result.scalars().first()
        
        mac_hex = f"52:54:00:{random.randint(10,99)}:{random.randint(10,99)}:{t['ip_offset']:02x}"
        
        if not asset:
            asset = Asset(
                ip_address=ip,
                mac_address=mac_hex,
                hostname=t["hostname"],
                device_type=t["device_type"],
                vendor=t["vendor"],
                os_name=t["os_name"],
                os_version=t["os_version"],
                open_ports=t["open_ports"],
                services=t["services"],
                is_iot=t["is_iot"],
                is_cctv=t["is_cctv"],
                firmware_version=t.get("firmware_version"),
                cctv_stream_protocol=t.get("cctv_stream_protocol"),
                subnet=target_subnet,
                last_scanned=datetime.now(timezone.utc)
            )
            db.add(asset)
            await db.flush()
        else:
            asset.last_scanned = datetime.now(timezone.utc)
            asset.open_ports = t["open_ports"]
            asset.services = t["services"]
            asset.os_version = t["os_version"]
        
        # Calculate risk score
        vulns_res = await db.execute(select(Vulnerability).where(Vulnerability.affected_asset_id == asset.id))
        vulns = vulns_res.scalars().all()
        
        alerts_res = await db.execute(select(Alert).where(Alert.affected_asset_id == asset.id))
        alerts = alerts_res.scalars().all()
        
        asset.risk_score = calculate_asset_risk(asset, vulns, alerts)
        discovered_count += 1
    
    await db.commit()
    
    await ws_manager.broadcast_scan_update(
        progress=100,
        status="COMPLETED",
        details={
            "subnet": target_subnet,
            "discovered_assets": discovered_count,
            "message": f"Scan completed. Discovered and fingerprinted {discovered_count} assets."
        }
    )
    
    await log_audit_event(
        db=db,
        action="ASSET_DISCOVERY_SCAN",
        resource="scanner",
        actor_email=actor_email,
        details={"subnet": target_subnet, "type": scan_type, "discovered": discovered_count}
    )
    
    return {
        "status": "success",
        "target_subnet": target_subnet,
        "scan_type": scan_type,
        "assets_discovered": discovered_count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
