from fastapi import APIRouter, HTTPException
import pandas as pd
import os

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry"])

# Define path to the processed sample data we created earlier
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, '..', '..', 'data', 'processed', 'sample_network_logs.parquet')

@router.get("/traffic")
def get_traffic_logs(limit: int = 50):
    """
    Fetches real network telemetry logs to power the analytics dashboard.
    """
    if not os.path.exists(DATA_PATH):
        raise HTTPException(status_code=404, detail="Processed telemetry data not found. Run preprocessing first.")
    
    # Read the parquet dataset
    df = pd.read_parquet(DATA_PATH)
    
    # Take a sample or slice based on the limit
    df_sample = df.head(limit)
    
    # Replace NaN or infinite values to ensure JSON compatibility
    import numpy as np
    df_sample = df_sample.replace([np.inf, -np.inf], 0).fillna(0)
    
    # Convert dataframe to dictionary records
    logs = df_sample.to_dict(orient="records")
    
    return {
        "status": "success",
        "count": len(logs),
        "data": logs
    }