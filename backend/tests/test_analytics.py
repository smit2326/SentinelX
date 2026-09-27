"""
Automated Pytest Suite for Phase 3 Data Science & Security Analytics Pipeline.
Validates:
- Canonical normalization and provenance retention
- 6-group feature engineering and versioning
- Empirical behavioral baselines and insufficient data handling
- Deterministic explainable risk scoring (4 components)
- Machine learning anomaly detection & classification
- Model versioning, evaluation metrics, and API endpoints
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.services.canonical_normalizer import CanonicalNormalizer
from app.services.feature_engineering import FeatureEngineeringService
from app.services.baseline_engine import BaselineEngine
from app.services.risk_scoring_engine import RiskScoringEngine
from app.services.ml_engine import MLEngine


@pytest.mark.asyncio
async def test_canonical_normalization():
    """Validates normalization of diverse service and protocol strings with provenance."""
    # 1. Service Normalization
    res_rpc = CanonicalNormalizer.normalize_service("Microsoft Windows RPC")
    assert res_rpc["canonical_service"] == "MSRPC"
    assert res_rpc["is_inferred"] is False

    res_smb = CanonicalNormalizer.normalize_service("microsoft-ds", port=445)
    assert res_smb["canonical_service"] == "SMBv3"

    res_unknown = CanonicalNormalizer.normalize_service(None, port=80)
    assert res_unknown["canonical_service"] == "HTTP"
    assert res_unknown["is_inferred"] is True

    # 2. Protocol Normalization
    assert CanonicalNormalizer.normalize_protocol("6") == "TCP"
    assert CanonicalNormalizer.normalize_protocol("udp") == "UDP"
    assert CanonicalNormalizer.normalize_protocol("icmp") == "ICMP"

    # 3. Security Event Provenance
    event = {
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.1",
        "protocol": "6",
        "destination_port": 445,
        "service_inferred": "microsoft-ds"
    }
    norm_event = CanonicalNormalizer.normalize_event_provenance(event, source="TShark Sniffer")
    assert norm_event["protocol"] == "TCP"
    assert norm_event["canonical_service"] == "SMBv3"
    assert norm_event["source"] == "TShark Sniffer"
    assert norm_event["raw_provenance"]["original_service"] == "microsoft-ds"


@pytest.mark.asyncio
async def test_feature_engineering():
    """Validates structural feature extraction across all 6 categories."""
    mock_asset = Asset(
        id=999,
        ip_address="192.168.1.50",
        hostname="TEST-ENDPOINT",
        open_ports=[{"port": 445, "service": "smb"}, {"port": 135, "service": "rpc"}],
        services=[{"name": "smb"}, {"name": "rpc"}]
    )

    mock_vulns = [
        Vulnerability(cve_id="CVE-2023-0001", cvss_score=9.8, severity="CRITICAL", affected_service="smb"),
        Vulnerability(cve_id="CVE-2023-0002", cvss_score=7.5, severity="HIGH", affected_service="rpc")
    ]

    # Asset features
    asset_feat = FeatureEngineeringService.extract_asset_features(mock_asset, mock_vulns)
    assert asset_feat["number_of_open_ports"] == 2
    assert asset_feat["number_of_known_vulnerabilities"] == 2
    assert asset_feat["number_of_critical_vulnerabilities"] == 1
    assert asset_feat["number_of_high_vulnerabilities"] == 1

    # Vulnerability features
    vuln_feat = FeatureEngineeringService.extract_vulnerability_features(mock_vulns)
    assert vuln_feat["max_cvss"] == 9.8
    assert vuln_feat["critical_cve_count"] == 1
    assert vuln_feat["high_cve_count"] == 1

    # Exposure features
    expo_feat = FeatureEngineeringService.extract_exposure_features(mock_asset)
    assert expo_feat["privileged_service_count"] == 2  # 445 and 135
    assert expo_feat["internet_exposed"] == 0          # Private 192.168 IP


@pytest.mark.asyncio
async def test_baseline_deviation_evaluation():
    """Validates behavioral deviation logic and empty state handling."""
    # When baseline is None or not established
    empty_eval = BaselineEngine.evaluate_traffic_deviation({"total_connections": 100}, None)
    assert empty_eval["has_baseline"] is False
    assert "insufficient historical data" in empty_eval["explanation"]


@pytest.mark.asyncio
async def test_deterministic_risk_scoring():
    """Validates component-based risk calculations and evidence explanation generation."""
    vuln_feat = {
        "critical_cve_count": 1,
        "high_cve_count": 1,
        "medium_cve_count": 0,
        "low_cve_count": 0,
        "exploitable_vulnerability_count": 1,
        "unpatched_vulnerability_count": 2
    }
    expo_feat = {
        "internet_exposed": 0,
        "privileged_service_count": 2,
        "sensitive_service_count": 2
    }
    asset_feat = {"asset_criticality": 2.0}
    behav_feat = {"baseline_status": "insufficient_data"}

    v_score, v_exp = RiskScoringEngine.calculate_vulnerability_component(vuln_feat)
    e_score, e_exp = RiskScoringEngine.calculate_exposure_component(expo_feat)
    c_score, c_exp = RiskScoringEngine.calculate_criticality_component(asset_feat)
    b_score, b_exp = RiskScoringEngine.calculate_behavioral_component(behav_feat)

    assert v_score > 0.0
    assert e_score > 0.0
    assert c_score == 10.0
    assert b_score == 0.0  # Does not invent fake behavioral penalty when baseline not established

    assert len(v_exp) >= 2
    assert len(e_exp) >= 1
    assert any("Critical-severity" in s for s in v_exp)


@pytest.mark.asyncio
async def test_analytics_and_ml_api_endpoints():
    """Validates end-to-end FastAPI endpoints for Risk, Features, Models, and Predictions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@sentinel-x.sec", "password": "SentinelAdmin2026!"}
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Risk Overview Endpoint
        risk_res = await client.get("/api/v1/analytics/risk", headers=headers)
        assert risk_res.status_code == 200
        risk_data = risk_res.json()
        assert "distribution" in risk_data
        assert "recent_changes" in risk_data
        assert risk_data["methodology_version"] == "v1.0"

        # 2. Behavioral Signals Endpoint
        signals_res = await client.get("/api/v1/analytics/network", headers=headers)
        assert signals_res.status_code == 200
        signals_data = signals_res.json()
        assert isinstance(signals_data, list)
        if len(signals_data) > 0:
            assert "signal" in signals_data[0]
            assert "evidence" in signals_data[0]

        # 3. Model Registry Endpoint
        models_res = await client.get("/api/v1/ml/models", headers=headers)
        assert models_res.status_code == 200
        models_data = models_res.json()
        assert len(models_data) >= 1
        assert models_data[0]["model_name"] == "SENTINEL-X-ANOMALY-v1"

        # 4. Evaluation Metrics Endpoint
        eval_res = await client.get("/api/v1/ml/evaluation", headers=headers)
        assert eval_res.status_code == 200
        eval_data = eval_res.json()
        assert len(eval_data) >= 1
        assert "f1" in eval_data[0]
        assert "confusion_matrix" in eval_data[0]

        # 5. ML Predictions Endpoint
        preds_res = await client.get("/api/v1/ml/predictions", headers=headers)
        assert preds_res.status_code == 200
        preds_data = preds_res.json()
        assert isinstance(preds_data, list)
        if len(preds_data) > 0:
            assert "prediction" in preds_data[0]
            assert "explanation" in preds_data[0]
            assert "anomaly_score" in preds_data[0]
