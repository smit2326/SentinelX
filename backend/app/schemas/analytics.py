"""
Phase 3 Analytics and Machine Learning Pydantic Schemas for SENTINEL-X.
Defines minimal, operational, evidence-oriented response models.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class FeatureSetOut(BaseModel):
    id: int
    asset_id: int
    timestamp: datetime
    feature_version: str
    asset_features: Dict[str, Any]
    vuln_features: Dict[str, Any]
    exposure_features: Dict[str, Any]
    network_features: Dict[str, Any]
    behavioral_features: Dict[str, Any]
    window_features: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class RiskAssessmentOut(BaseModel):
    id: int
    asset_id: int
    timestamp: datetime
    methodology_version: str
    risk_score: float
    risk_level: str
    vulnerability_component: float
    exposure_component: float
    criticality_component: float
    behavioral_component: float
    explanation_list: List[str]

    model_config = ConfigDict(from_attributes=True)


class RiskOverviewOut(BaseModel):
    total_assets_assessed: int
    distribution: Dict[str, int]  # {"Critical": 0, "High": 1, "Moderate": 0, "Low": 0}
    recent_changes: List[Dict[str, Any]]
    methodology_version: str


class BehavioralSignalOut(BaseModel):
    asset_id: int
    hostname: str
    ip_address: str
    signal: str
    evidence: str
    deviation_ratio: float
    recommended_action: str


class MLPredictionOut(BaseModel):
    id: int
    asset_id: int
    timestamp: datetime
    model_version: str
    prediction: str
    anomaly_score: Optional[float] = None
    probability: Optional[float] = None
    explanation: List[str]
    recommended_action: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ModelVersionOut(BaseModel):
    id: int
    model_name: str
    version: str
    algorithm: str
    dataset_version: str
    feature_version: str
    status: str
    training_date: datetime
    metrics_summary: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class EvaluationResultOut(BaseModel):
    id: int
    model_version_id: int
    test_dataset: str
    timestamp: datetime
    precision: float
    recall: float
    f1: float
    confusion_matrix: Dict[str, Any]
    fp_count: int
    fn_count: int
    false_positive_analysis: Optional[str] = None
    false_negative_analysis: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
