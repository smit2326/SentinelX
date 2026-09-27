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
