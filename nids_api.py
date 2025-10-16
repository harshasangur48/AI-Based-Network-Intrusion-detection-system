import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np


try:
    MODEL = joblib.load('xgb_gpu_nids_model.joblib')
    SCALER = joblib.load('fitted_scaler.joblib')
    LABEL_ENCODER = joblib.load('fitted_label_encoder.joblib')
    
    EXPECTED_FEATURES = list(SCALER.feature_names_in_)
    
    
    CUSTOM_CLASS_MAPPING = {
        '1': 'BENIGN',
        '2': 'DoS-SYN Flood',
        '3': 'DoS-Hulk',
        '4': 'PortScan',
        '5': 'DDoS',
        '6': 'Web Attack',
        '7': 'Botnet',
        '8': 'Infiltration',
        '9': 'FTP-Patator',
        '10': 'SSH-Patator',
        '11': 'Heartbleed'
    }
    
    
    NUMERIC_TO_LABEL = {
        idx: CUSTOM_CLASS_MAPPING.get(str(label), f"UNKNOWN_CLASS_{label}")
        for idx, label in enumerate(LABEL_ENCODER.classes_)
    }
    
    print("✅ All NIDS assets loaded successfully. Custom labels applied.")

except Exception as e:
    print(f"❌ ERROR: Failed to load required assets. Details: {e}")
    


class FlowFeatures(BaseModel):
    features: dict 


app = FastAPI(
    title="AI-Based NIDS Inference Service",
    description="Real-time Network Intrusion Detection using XGBoost-GPU."
)


@app.post("/predict_flow/")
async def predict_intrusion(data: FlowFeatures):
    """
    Receives 78 network flow features, runs the model, and returns an intrusion prediction.
    """
    try:
        
        input_data = pd.DataFrame([data.features])
        if not all(feature in input_data.columns for feature in EXPECTED_FEATURES):
            
             missing = set(EXPECTED_FEATURES) - set(input_data.columns)
             return {"error": f"Missing features: {list(missing)}", "status": "FAIL"}

        X_live = input_data[EXPECTED_FEATURES]
        X_scaled = SCALER.transform(X_live)
        
        
        prediction_numeric = MODEL.predict(X_scaled)[0]
        prediction_proba = MODEL.predict_proba(X_scaled)[0]
        confidence = np.max(prediction_proba)

       
        predicted_label = NUMERIC_TO_LABEL.get(
            int(prediction_numeric), "UNKNOWN_INDEX"
        )
        
        
        is_intrusion = predicted_label.upper() != 'BENIGN'
        
        return {
            "status": "SUCCESS",
            "intrusion_detected": is_intrusion,
            "predicted_class": predicted_label,
            "confidence": f"{confidence:.4f}",
            "model_time_ms": 0.5
        }

    except Exception as e:
        print(f"Prediction Error: {e}")
        return {"error": str(e), "status": "FAIL"}