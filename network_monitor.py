import requests
import time
import numpy as np
import joblib

NIDS_API_URL = "http://127.0.0.1:8000/predict_flow/"


try:
    
    DUMMY_SCALER = joblib.load('fitted_scaler.joblib')
    EXPECTED_FEATURES = list(DUMMY_SCALER.feature_names_in_)
except Exception as e:
    print(f"Warning: Could not load scaler for feature names. Using dummy names.")
    EXPECTED_FEATURES = [f"Feature_{i}" for i in range(1, 79)]


def extract_78_features(packet_data):
    """
    *** CRITICAL: REPLACE THIS DUMMY LOGIC ***

    This function must be replaced with the actual code that reads raw network 
    packets (e.g., using scapy, or parsing NetFlow/Zeek logs) and calculates 
    the EXACT 78 features your model was trained on (e.g., Flow Duration, Fwd Pkt Len Max).
    """
    
    
    features_dict = {
        name: float(np.random.uniform(0, 100)) for name in EXPECTED_FEATURES
    }
    
    
    
    return features_dict

def send_for_prediction(features):
    """Sends extracted flow features to the NIDS API."""
    payload = {"features": features}
    try:
        response = requests.post(NIDS_API_URL, json=payload, timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        alert_data = response.json()
        
        if alert_data.get("intrusion_detected"):
            print(f"🔥 **ALERT:** Intrusion Detected: {alert_data['predicted_class']} (Confidence: {alert_data['confidence']})")
        else:
            print(f"✅ Flow is BENIGN. (Confidence: {alert_data['confidence']})")
            
        return alert_data
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Connection Error. Is 'nids_api.py' running? Details: {e}")
        return None

def continuous_monitor_loop():
    """Simulates continuous network monitoring by repeatedly calling the API."""
    print("Starting continuous network monitor...")
    
    while True:
        flow_features = extract_78_features(None)
        send_for_prediction(flow_features)
        
       
        time.sleep(0.1) 

if __name__ == "__main__":
    
    continuous_monitor_loop()