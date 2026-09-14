import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.db.seed_data import init_and_seed_db

@pytest_asyncio.fixture(autouse=True)
async def prepare_db():
    await init_and_seed_db()

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
async def test_asset_inventory_and_quarantine():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        admin_login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        token = admin_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # List assets
        assets_res = await client.get("/api/v1/assets", headers=headers)
        assert assets_res.status_code == 200
        assets = assets_res.json()
        assert len(assets) > 0
        
        # Toggle quarantine on first asset
        first_asset = assets[0]
        q_res = await client.post(f"/api/v1/assets/{first_asset['id']}/quarantine", headers=headers)
        assert q_res.status_code == 200
        assert "is_quarantined" in q_res.json()["asset"]
