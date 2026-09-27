"""
Phase 3 Machine Learning & Anomaly Detection API Router for SENTINEL-X.
Exposes predictions, model registries, and empirical evaluation metrics.
Adheres strictly to the principle of returning analyst-ready conclusions rather than raw math internals.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.models.user import User
from app.models.asset import Asset
from app.models.analytics import MLPrediction, ModelVersion, EvaluationResult
from app.schemas.analytics import (
    MLPredictionOut,
    ModelVersionOut,
    EvaluationResultOut
)
from app.services.auth_service import require_any_authenticated, require_analyst_or_admin
from app.services.ml_engine import MLEngine

router = APIRouter(prefix="/ml", tags=["Phase 3 — Machine Learning & Anomaly Detection"])


@router.get("/predictions", response_model=List[MLPredictionOut])
async def get_latest_predictions(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns the latest machine-learning inferences across active endpoints.
    Provides plain-English explanations and recommended analyst actions.
    """
    assets_res = await db.execute(select(Asset))
    assets = assets_res.scalars().all()
    predictions: List[MLPredictionOut] = []

    for a in assets:
        stmt = (
            select(MLPrediction)
            .where(MLPrediction.asset_id == a.id)
            .order_by(MLPrediction.timestamp.desc())
        )
        res = await db.execute(stmt)
        latest = res.scalars().first()

        if not latest:
            latest = await MLEngine.predict_asset_behavior(db, a.id)

        predictions.append(latest)

    return predictions


@router.post("/predict/{asset_id}", response_model=MLPredictionOut)
async def run_asset_prediction(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_analyst_or_admin)
):
    """
    Executes fresh machine learning inference on an asset's current feature vector.
    """
    asset_res = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = asset_res.scalars().first()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    return await MLEngine.predict_asset_behavior(db, asset_id)


@router.get("/models", response_model=List[ModelVersionOut])
async def get_model_registry(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns versioned models active in the SENTINEL-X Model Registry.
    """
    # Ensure baseline models are registered
    stmt = select(ModelVersion)
    res = await db.execute(stmt)
    models = res.scalars().all()

    if not models:
        await MLEngine.train_or_load_models(db)
        res = await db.execute(select(ModelVersion))
        models = res.scalars().all()

    return models


@router.get("/evaluation", response_model=List[EvaluationResultOut])
async def get_model_evaluations(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(require_any_authenticated)
):
    """
    Returns empirical evaluation reports (Precision, Recall, F1, Confusion Matrix, FP/FN analysis)
    for models evaluated on held-out test splits.
    """
    stmt = select(EvaluationResult).order_by(EvaluationResult.timestamp.desc())
    res = await db.execute(stmt)
    evals = res.scalars().all()

    if not evals:
        await MLEngine.train_or_load_models(db)
        res = await db.execute(select(EvaluationResult).order_by(EvaluationResult.timestamp.desc()))
        evals = res.scalars().all()

    return evals
