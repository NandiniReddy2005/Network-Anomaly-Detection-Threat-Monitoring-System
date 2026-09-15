from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from typing import Optional

try:
    from app.database import get_db
    from app.services.ml_manager import ml_manager
except ImportError:
    from backend.app.database import get_db
    from backend.app.services.ml_manager import ml_manager

router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])

@router.get("/status")
async def get_ml_status(db: AsyncSession = Depends(get_db)):
    """
    Returns health check & model loading status for UNSW-NB15 and CICIDS2017 ML artifacts.
    Dynamic feature counts and class counts are reported directly from loaded artifacts.
    """
    status_data = ml_manager.get_status()
    return {
        "status": "success",
        "data": status_data
    }

@router.get("/metadata/{dataset}")
async def get_dataset_metadata(dataset: str, db: AsyncSession = Depends(get_db)):
    """
    Returns feature names, threat classes, Colab metadata, and dynamic counts for the specified dataset.
    Supported values: UNSW_NB15 (or unsw-nb15), CICIDS2017 (or cicids2017).
    """
    normalized_name = dataset.upper().replace("-", "_")
    if normalized_name not in ["UNSW_NB15", "CICIDS2017"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset '{dataset}' not recognized. Supported datasets: UNSW_NB15, CICIDS2017."
        )

    metadata = ml_manager.get_metadata(normalized_name)
    if not metadata:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Metadata for dataset '{dataset}' not available."
        )

    return {
        "status": "success",
        "data": metadata
    }
