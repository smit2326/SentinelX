import asyncio
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.seed_data import init_and_seed_db

_db_initialized = False

@pytest_asyncio.fixture(autouse=True)
async def prepare_db():
    global _db_initialized
    if not _db_initialized:
        await init_and_seed_db()
        _db_initialized = True

@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "HEALTHY"

@pytest.mark.asyncio
async def test_admin_login():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"

@pytest.mark.asyncio
async def test_analyst_login():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@sentinel-x.sec", "password": "SentinelAnalyst2026!"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["role"] == "analyst"

@pytest.mark.asyncio
async def test_rbac_user_management():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Analyst login
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@sentinel-x.sec", "password": "SentinelAnalyst2026!"}
        )
        analyst_token = analyst_login.json()["access_token"]
        
        # 2. Analyst tries to view user management (Forbidden for non-admins)
        analyst_res = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {analyst_token}"}
        )
        assert analyst_res.status_code == 403

        # 3. Admin login
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        admin_token = admin_login.json()["access_token"]
        
        # 4. Admin accesses user management
        admin_res = await client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert admin_res.status_code == 200
        assert len(admin_res.json()) >= 3

@pytest.mark.asyncio
async def test_real_asset_scan_and_inventory():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        token = admin_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Run real network discovery on 127.0.0.1
        scan_res = await client.post(
            "/api/v1/assets/scan",
            headers=headers,
            json={"target_subnet": "127.0.0.1", "scan_type": "quick"}
        )
        assert scan_res.status_code == 200
        assert scan_res.json()["status"] == "SCAN_DISPATCHED"

        # List assets (should not contain fake demo CCTV/HVAC IPs)
        assets_res = await client.get("/api/v1/assets", headers=headers)
        assert assets_res.status_code == 200
        assets = assets_res.json()
        for a in assets:
            assert a["ip_address"] != "192.168.1.45"
            assert a["ip_address"] != "192.168.1.72"

@pytest.mark.asyncio
async def test_network_interfaces_and_captures():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        analyst_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@sentinel-x.sec", "password": "SentinelAnalyst2026!"}
        )
        token = analyst_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Check network interfaces
        if_res = await client.get("/api/v1/network/interfaces", headers=headers)
        assert if_res.status_code == 200
        assert len(if_res.json()) >= 1

        # 2. Start a real capture on loopback
        start_res = await client.post(
            "/api/v1/network/captures/start",
            headers=headers,
            json={
                "interface": "lo",
                "duration_seconds": 2,
                "capture_source": "TCPDump Test"
            }
        )
        assert start_res.status_code == 200
        cap_data = start_res.json()
        cap_id = cap_data["capture_id"]

        # 3. Stop capture
        stop_res = await client.post(
            "/api/v1/network/captures/stop",
            headers=headers,
            json={"capture_id": cap_id}
        )
        assert stop_res.status_code == 200
        assert stop_res.json()["status"] in ["COMPLETED", "ANALYZED"]

        # 4. Check traffic dashboard stats
        traffic_res = await client.get("/api/v1/network/traffic", headers=headers)
        assert traffic_res.status_code == 200
        assert "visibility_disclaimer" in traffic_res.json()

        # 5. Check PCAP download for Wireshark
        dl_res = await client.get(f"/api/v1/network/captures/{cap_id}/download", headers=headers)
        assert dl_res.status_code == 200
        assert dl_res.headers["content-type"] == "application/vnd.tcpdump.pcap"

@pytest.mark.asyncio
async def test_nmap_status_and_laptop_audit():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Check Nmap status
        status_res = await client.get("/api/v1/assets/nmap/status", headers=headers)
        assert status_res.status_code == 200
        data = status_res.json()
        assert "installed" in data
        assert "host" in data
        assert "hostname" in data["host"]

        # Check vulnerabilities listing
        vulns_res = await client.get("/api/v1/vulnerabilities", headers=headers)
        assert vulns_res.status_code == 200
        assert isinstance(vulns_res.json(), list)

@pytest.mark.asyncio
async def test_openvas_integration():
    """Validates OpenVAS status, test connection, and report ingestion."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. OpenVAS status
        status_res = await client.get("/api/v1/openvas/status", headers=headers)
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert "supported_formats" in status_data
        assert "host" in status_data

        # 2. OpenVAS connection test (unreachable port test)
        conn_res = await client.post("/api/v1/openvas/test-connection", headers=headers)
        assert conn_res.status_code == 200
        assert "status" in conn_res.json()

        # 3. OpenVAS sample report import (Router, CCTV, Server)
        import_res = await client.post("/api/v1/openvas/import-sample", headers=headers)
        assert import_res.status_code == 200
        import_data = import_res.json()
        assert import_data["success"] is True
        total_vulns = import_data["new_vulnerabilities"] + import_data["updated_vulnerabilities"]
        assert total_vulns >= 3
        assert import_data["assets_affected"] >= 3

        # 4. Verify ingested CVEs in vulnerability catalog
        vulns_res = await client.get("/api/v1/vulnerabilities", headers=headers)
        assert vulns_res.status_code == 200
        cves = [v["cve_id"] for v in vulns_res.json()]
        assert "CVE-2023-1389" in cves   # Router
        assert "CVE-2021-36260" in cves  # CCTV Camera
        assert "CVE-2023-38408" in cves  # Server

        # Clean up test-created assets using the API to keep live inventory pristine
        assets_res = await client.get("/api/v1/assets", headers=headers)
        if assets_res.status_code == 200:
            test_ips = {"192.168.1.1", "192.168.1.65", "192.168.1.200"}
            for a in assets_res.json():
                if a["ip_address"] in test_ips:
                    await client.delete(f"/api/v1/assets/{a['id']}", headers=headers)

@pytest.mark.asyncio
async def test_data_cleaning_pipeline():
    """Validates the 7 core components of the Phase 3 Data Cleaning Pipeline."""
    from app.services.data_cleaning_pipeline import DataCleaningPipeline

    # A. Remove duplicates test
    raw_records = [
        {"ip": "10.0.0.1", "port": 80, "val": "first"},
        {"ip": "10.0.0.1", "port": 80, "val": "duplicate"},
        {"ip": "10.0.0.2", "port": 443, "val": "unique"}
    ]
    deduped, removed = DataCleaningPipeline.deduplicate_records(raw_records, ["ip", "port"])
    assert len(deduped) == 2
    assert removed == 1

    # B. Normalize Operating Systems
    win_norm = DataCleaningPipeline.normalize_os("Microsoft Windows 11 Home 26100")
    assert win_norm["os_family"] == "Windows"
    assert win_norm["os_version"] == "11"
    assert win_norm["os_build"] == "26100"

    linux_norm = DataCleaningPipeline.normalize_os("Ubuntu 22.04.3 LTS")
    assert linux_norm["os_family"] == "Linux"

    cctv_norm = DataCleaningPipeline.normalize_os("Hikvision Embedded Camera")
    assert cctv_norm["os_family"] == "Embedded IoT"

    # C. Normalize Software Versions
    ssh_norm = DataCleaningPipeline.normalize_software_version("OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
    assert ssh_norm["product"] == "Openssh"
    assert ssh_norm["version"] == "8.9p1"
    assert ssh_norm["major"] == 8

    # D. Handle Missing Values without synthetic hallucination
    missing_handled = DataCleaningPipeline.handle_missing_values({
        "ip_address": "127.0.0.1",
        "hostname": None,
        "mac_address": "bc:ba:e1:12:34:56", # Hikvision OUI
        "open_ports": [{"port": 554, "service": "rtsp"}],
        "device_type": None
    })
    assert missing_handled["vendor"] == "Hikvision Digital Technology"
    assert missing_handled["device_type"] == "CCTV Camera"
    assert missing_handled["hostname"] is None  # Not blindly hallucinated

    # E. Validate IP Addresses
    assert DataCleaningPipeline.validate_ip("192.168.1.1")["is_valid"] is True
    assert DataCleaningPipeline.validate_ip("192.168.1.1")["is_private"] is True
    assert DataCleaningPipeline.validate_ip("999.999.999.999")["is_valid"] is False
    assert DataCleaningPipeline.validate_ip("invalid-host")["is_valid"] is False

    # F. Validate Ports
    assert DataCleaningPipeline.validate_port(443)["is_valid"] is True
    assert DataCleaningPipeline.validate_port(443)["port_class"] == "Well-Known"
    assert DataCleaningPipeline.validate_port(8080)["port_class"] == "Registered"
    assert DataCleaningPipeline.validate_port(0)["is_valid"] is False
    assert DataCleaningPipeline.validate_port(70000)["is_valid"] is False

    # G. Normalize Timestamps
    epoch_ts = DataCleaningPipeline.normalize_timestamp(1727438400)
    assert epoch_ts is not None
    assert epoch_ts.tzinfo is not None

    iso_ts = DataCleaningPipeline.normalize_timestamp("2026-09-27T12:00:00Z")
    assert iso_ts is not None

    # Test API Endpoints
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Status
        status_res = await client.get("/api/v1/cleaning/status", headers=headers)
        assert status_res.status_code == 200
        assert "pipeline_steps" in status_res.json()

        # Validation endpoints
        ip_res = await client.post("/api/v1/cleaning/validate-ip", headers=headers, json={"ip": "10.0.0.1"})
        assert ip_res.status_code == 200
        assert ip_res.json()["is_private"] is True

        port_res = await client.post("/api/v1/cleaning/validate-port", headers=headers, json={"port": 445})
        assert port_res.status_code == 200
        assert port_res.json()["standard_service"] == "SMBv3"

        # Execute pipeline on database
        run_res = await client.post("/api/v1/cleaning/run", headers=headers)
        assert run_res.status_code == 200
        assert run_res.json()["success"] is True
        assert "cleaning_report" in run_res.json()

@pytest.mark.asyncio
async def test_data_quality_layer():
    """
    Validates Phase 3 Component 3: Data Quality Layer.
    Verifies lineage passports, source credibility, confidence scoring,
    and non-destructive retention ('Don't just clean the data and throw bad records away').
    """
    from app.services.data_quality_layer import DataQualityLayer

    # 1. Complete Record Assessment (Exact User Specification)
    sample_complete = {
        "ip_address": "127.0.0.1",
        "hostname": "PAVILION_23",
        "os_name": "Windows 11",
        "os_build": "26100",
        "vendor": "HP / Microsoft",
        "mac_address": "00:15:5d:01:02:03",
        "open_ports": [{"port": 445, "service": "smb"}],
        "collection_time": "2026-09-27"
    }
    passport = DataQualityLayer.assess_record_quality(sample_complete, source="Windows Collector")
    assert passport["os"] == "Windows 11"
    assert passport["os_build"] == "26100"
    assert passport["source"] == "Windows Collector"
    assert passport["confidence"] == "High"
    assert passport["collection_time"] == "2026-09-27"
    assert passport["data_quality"] == "Complete"
    assert passport["completeness_score"] == 100.0

    # 2. Incomplete / Partial Record Assessment (Do NOT throw bad records away)
    sample_partial = {
        "ip_address": "10.0.0.99",
        "hostname": "UNKNOWN-DEV"
    }
    partial_passport = DataQualityLayer.assess_record_quality(sample_partial, source="Passive Flow Sighting")
    assert partial_passport["data_quality"] in ["Partial", "Degraded"]
    assert partial_passport["confidence"] == "Low"
    assert len(partial_passport["missing_fields"]) > 0

    # 3. Test API Endpoints
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Quality Evaluate endpoint
        eval_res = await client.post(
            "/api/v1/cleaning/quality/evaluate",
            headers=headers,
            json={
                "ip_address": "127.0.0.1",
                "hostname": "PAVILION_23",
                "os_name": "Windows 11",
                "os_build": "26100",
                "source": "Windows Collector"
            }
        )
        assert eval_res.status_code == 200
        data = eval_res.json()
        assert data["os"] == "Windows 11"
        assert data["os_build"] == "26100"
        assert data["source"] == "Windows Collector"
        assert data["confidence"] == "High"
        assert data["data_quality"] == "Complete"

        # Quality Summary endpoint
        summary_res = await client.get("/api/v1/cleaning/quality/summary", headers=headers)
        assert summary_res.status_code == 200
        summary_data = summary_res.json()
        assert "quality_distribution" in summary_data
        assert "confidence_distribution" in summary_data
        assert summary_data["total_assets"] >= 1

        # Quality Audit endpoint
        audit_res = await client.post("/api/v1/cleaning/quality/audit", headers=headers)
        assert audit_res.status_code == 200
        audit_data = audit_res.json()
        assert audit_data["success"] is True
        assert "audit_report" in audit_data
