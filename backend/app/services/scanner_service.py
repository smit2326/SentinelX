import asyncio
import socket
import ipaddress
import platform
from typing import Dict, Any, List, Optional
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

COMMON_PORTS = [
    (21, "ftp", "FTP"),
    (22, "ssh", "OpenSSH"),
    (53, "dns", "DNS"),
    (80, "http", "HTTP"),
    (135, "msrpc", "Microsoft RPC"),
    (139, "netbios-ssn", "NetBIOS"),
    (443, "https", "HTTPS"),
    (445, "microsoft-ds", "SMBv3"),
    (554, "rtsp", "RTSP"),
    (3389, "ms-wbt-server", "RDP"),
    (5432, "postgresql", "PostgreSQL"),
    (8000, "http-alt", "FastAPI / Uvicorn"),
    (8080, "http-alt", "HTTP-Proxy")
]

async def probe_port(ip: str, port: int, timeout: float = 0.35) -> Optional[Dict[str, Any]]:
    """Probes a single TCP port using real asynchronous socket connection."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        
        # Inferred service name
        service_name = "unknown"
        banner = None
        for p, s, b in COMMON_PORTS:
            if p == port:
                service_name = s
                banner = b
                break

        return {
            "port": port,
            "protocol": "tcp",
            "service": service_name,
            "state": "open",
            "version": banner or f"Port {port} service"
        }
    except Exception:
        return None

async def scan_single_host(ip: str, ports_to_scan: List[int]) -> Optional[Dict[str, Any]]:
    """Scans ports on a specific IP. Returns asset data only if at least one port is open."""
    open_ports = []
    tasks = [probe_port(ip, port) for port in ports_to_scan]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for r in results:
        if isinstance(r, dict) and r:
            open_ports.append(r)
            
    if not open_ports:
        return None

    # Resolve real hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None

    device_type = "Workstation"
    os_name = platform.system() if ip in ["127.0.0.1", "localhost"] else "Network Host"
    is_cctv = any(p["port"] == 554 for p in open_ports)
    if is_cctv:
        device_type = "CCTV Camera"
    elif any(p["port"] in [445, 135, 3389] for p in open_ports):
        device_type = "Server" if "server" in (hostname or "").lower() else "Workstation"
    elif any(p["port"] in [80, 443, 8000, 8080] for p in open_ports):
        device_type = "Web Server / Gateway"

    services = [{"name": p["service"], "version": p.get("version", "")} for p in open_ports]

    return {
        "ip_address": ip,
        "hostname": hostname,
        "device_type": device_type,
        "vendor": "Local / Discovered",
        "os_name": os_name,
        "os_version": platform.release() if ip in ["127.0.0.1", "localhost"] else None,
        "open_ports": open_ports,
        "services": services,
        "is_iot": is_cctv,
        "is_cctv": is_cctv,
        "cctv_stream_protocol": "RTSP" if is_cctv else None
    }

async def execute_network_discovery(
    db: AsyncSession,
    target_subnet: str,
    scan_type: str,
    actor_email: str
) -> Dict[str, Any]:
    logger.info(f"Initiating real network discovery scan on {target_subnet} (Type: {scan_type}) by {actor_email}")
    
    await ws_manager.broadcast_scan_update(
        progress=10,
        status="INITIALIZING_PROBES",
        details={"subnet": target_subnet, "message": f"Parsing CIDR range and initializing real socket probes on {target_subnet}"}
    )
    
    # Parse target IPs
    hosts_to_scan: List[str] = []
    try:
        if "/" in target_subnet:
            net = ipaddress.ip_network(target_subnet, strict=False)
            # Limit scan to max 32 hosts to keep execution fast and prevent timeouts
            hosts_to_scan = [str(ip) for ip in list(net.hosts())[:32]]
        else:
            hosts_to_scan = [target_subnet.strip()]
    except Exception:
        # Fallback to localhost and local gateway
        hosts_to_scan = ["127.0.0.1"]

    # Always include 127.0.0.1 if target is 127.0.0.1 or contains it
    if not hosts_to_scan:
        hosts_to_scan = ["127.0.0.1"]

    ports_to_scan = [p[0] for p in COMMON_PORTS]
    if scan_type == "quick":
        ports_to_scan = [80, 443, 8000, 22, 445]
    elif scan_type == "cctv_iot":
        ports_to_scan = [554, 80, 8080, 502]

    await ws_manager.broadcast_scan_update(
        progress=40,
        status="ACTIVE_SOCKET_PROBING",
        details={"subnet": target_subnet, "message": f"Actively probing {len(hosts_to_scan)} hosts across {len(ports_to_scan)} TCP ports..."}
    )

    discovered_hosts = []
    for idx, host_ip in enumerate(hosts_to_scan):
        host_info = await scan_single_host(host_ip, ports_to_scan)
        if host_info:
            discovered_hosts.append(host_info)
        prog = 40 + int((idx / len(hosts_to_scan)) * 45)
        await ws_manager.broadcast_scan_update(
            progress=prog,
            status="PORT_FINGERPRINTING",
            details={"subnet": target_subnet, "message": f"Inspected {host_ip} ({len(discovered_hosts)} responsive host(s) found so far)"}
        )

    # Save real discovered hosts to database
    discovered_count = 0
    for h in discovered_hosts:
        stmt = select(Asset).where(Asset.ip_address == h["ip_address"])
        result = await db.execute(stmt)
        asset = result.scalars().first()

        if not asset:
            asset = Asset(
                ip_address=h["ip_address"],
                hostname=h["hostname"],
                device_type=h["device_type"],
                vendor=h["vendor"],
                os_name=h["os_name"],
                os_version=h["os_version"],
                open_ports=h["open_ports"],
                services=h["services"],
                is_iot=h["is_iot"],
                is_cctv=h["is_cctv"],
                cctv_stream_protocol=h["cctv_stream_protocol"],
                subnet=target_subnet,
                last_scanned=datetime.now(timezone.utc)
            )
            db.add(asset)
            await db.flush()
        else:
            asset.last_scanned = datetime.now(timezone.utc)
            asset.open_ports = h["open_ports"]
            asset.services = h["services"]
            if h["hostname"]:
                asset.hostname = h["hostname"]

        # Calculate actual risk score based on open ports
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
            "message": f"Real active scan completed. Identified {discovered_count} responsive host(s)."
        }
    )

    await log_audit_event(
        db=db,
        action="REAL_ASSET_DISCOVERY_SCAN",
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
