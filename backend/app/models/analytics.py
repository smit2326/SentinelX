"""
Phase 3 Unified Analytics, Feature Engineering, Risk Assessment, and ML Models.
Defines canonical database entities for security data science, baseline tracking,
reproducible datasets, model registries, and explainable risk results.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, ForeignKey
from app.core.database import Base


class FeatureSet(Base):
    """
    Stores versioned security feature vectors extracted from Phase 1 and Phase 2 data.
    Ensures that every ML prediction and risk assessment is reproducible.
    """
    __tablename__ = "feature_sets"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    feature_version = Column(String(50), default="v1.0", nullable=False, index=True)

    # Granular Feature Categories
    asset_features = Column(JSON, default=dict)       # ports, services, OS, criticality
    vuln_features = Column(JSON, default=dict)        # cve counts, max/avg cvss, exploitability
    exposure_features = Column(JSON, default=dict)    # reachable ports, sensitive services (SMB, RDP)
    network_features = Column(JSON, default=dict)     # conn rates, packet counts, bytes, dns count
    behavioral_features = Column(JSON, default=dict)  # deviations from baseline, new ports, failed conns
    window_features = Column(JSON, default=dict)      # 5m, 15m, 1h, 24h rolling aggregations

    # Full flat vector for ML models
    feature_vector = Column(JSON, default=dict)

    def __repr__(self):
        return f"<FeatureSet asset={self.asset_id} ver={self.feature_version} time={self.timestamp}>"


class BehavioralBaseline(Base):
    """
    Maintains learned behavioral baselines for an asset or device peer group.
    Flags 'insufficient_data' if historical depth is inadequate.
    """
    __tablename__ = "behavioral_baselines"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    baseline_version = Column(String(50), default="v1.0", nullable=False)
    sample_count = Column(Integer, default=0)

    # Baseline statistical metrics (mean, std dev, or median)
    normal_conn_per_hour = Column(Float, default=0.0)
    normal_dns_per_hour = Column(Float, default=0.0)
    normal_destinations = Column(Float, default=0.0)
    normal_bytes_per_hour = Column(Float, default=0.0)

    # Status: 'established', 'learning', 'insufficient_data'
    status = Column(String(50), default="insufficient_data", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<BehavioralBaseline asset={self.asset_id} status={self.status} conns={self.normal_conn_per_hour}>"


class RiskAssessment(Base):
    """
    Deterministic and explainable security risk assessment.
    Formula: Risk = Vuln Component + Exposure Component + Criticality + Behavioral Component.
    """
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    methodology_version = Column(String(50), default="v1.0", nullable=False)

    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0
    risk_level = Column(String(50), default="Low", nullable=False, index=True)  # Low, Moderate, High, Critical

    # Explainable Component Scores
    vulnerability_component = Column(Float, default=0.0)  # Max 40
    exposure_component = Column(Float, default=0.0)       # Max 25
    criticality_component = Column(Float, default=0.0)    # Max 20
    behavioral_component = Column(Float, default=0.0)     # Max 15

    # Evidence-grounded explanations
    explanation_list = Column(JSON, default=list)  # ["2 high-severity CVEs", "network activity above baseline"]

    def __repr__(self):
        return f"<RiskAssessment asset={self.asset_id} score={self.risk_score} level={self.risk_level}>"


class ModelVersion(Base):
    """
    Model Registry entity tracking trained machine learning models,
    hyperparameters, datasets, and operational lifecycle.
    """
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String(100), nullable=False, index=True)  # e.g. SENTINEL-X-ANOMALY-v1
    version = Column(String(50), nullable=False)                  # e.g. 1.0.0
    algorithm = Column(String(100), nullable=False)                # e.g. Isolation Forest, Random Forest
    dataset_version = Column(String(100), default="dataset_2026_09_v1")
    feature_version = Column(String(50), default="v1.0")

    training_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(String(50), default="Production", nullable=False)  # Production, Staging, Deprecated
    hyperparameters = Column(JSON, default=dict)
    metrics_summary = Column(JSON, default=dict)
    model_artifact_path = Column(String(255), nullable=True)

    def __repr__(self):
        return f"<ModelVersion {self.model_name}:{self.version} ({self.status})>"


class MLPrediction(Base):
    """
    Stores inferences produced by machine learning models.
    Distinguishes observations from statistical predictions.
    """
    __tablename__ = "ml_predictions"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    model_version = Column(String(100), nullable=False, index=True)

    prediction = Column(String(100), nullable=False)  # e.g. "Anomalous Behavior", "Normal Operation", "Suspicious"
    probability = Column(Float, nullable=True)         # 0.0 to 1.0 where applicable
    anomaly_score = Column(Float, nullable=True)       # 0.0 to 1.0 where applicable

    important_features = Column(JSON, default=list)    # [{"feature": "conn_rate", "importance": 0.42}]
    explanation = Column(JSON, default=list)           # Human-readable analyst explanation
    recommended_action = Column(Text, nullable=True)   # "Review recent network connections and associated PCAP"

    def __repr__(self):
        return f"<MLPrediction asset={self.asset_id} pred={self.prediction} score={self.anomaly_score}>"


class EvaluationResult(Base):
    """
    Stores empirical performance metrics for trained models on test splits.
    Includes Precision, Recall, F1, Confusion Matrix, and FP/FN tallies.
    """
    __tablename__ = "evaluation_results"

    id = Column(Integer, primary_key=True, index=True)
    model_version_id = Column(Integer, ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    test_dataset = Column(String(100), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    precision = Column(Float, default=0.0)
    recall = Column(Float, default=0.0)
    f1 = Column(Float, default=0.0)
    roc_auc = Column(Float, nullable=True)
    pr_auc = Column(Float, nullable=True)

    confusion_matrix = Column(JSON, default=dict)  # {"tp": 42, "tn": 150, "fp": 3, "fn": 2}
    fp_count = Column(Integer, default=0)
    fn_count = Column(Integer, default=0)
    false_positive_analysis = Column(Text, nullable=True)
    false_negative_analysis = Column(Text, nullable=True)

    def __repr__(self):
        return f"<EvaluationResult model={self.model_version_id} F1={self.f1} P={self.precision} R={self.recall}>"


class DatasetRecord(Base):
    """
    Metadata registry for reproducible security analytics datasets.
    """
    __tablename__ = "datasets"

    id = Column(Integer, primary_key=True, index=True)
    dataset_id = Column(String(100), unique=True, nullable=False, index=True)  # e.g. dataset_2026_09_v1
    source = Column(String(150), default="SENTINEL-X Telemetry", nullable=False)
    collection_period = Column(String(100), nullable=False)
    feature_version = Column(String(50), default="v1.0", nullable=False)
    sample_count = Column(Integer, default=0)
    label_methodology = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<DatasetRecord {self.dataset_id} samples={self.sample_count}>"
