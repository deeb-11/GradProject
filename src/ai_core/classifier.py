# ai_core/classifier.py

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Model will be saved/loaded from this path
MODEL_PATH = os.path.join(os.path.dirname(__file__), "vuln_model.pkl")

def init_model(data_file: str = None):
    """
    Load a saved model if available, otherwise train a new one using
    the dataset located at ../../data/vuln_data.csv
    """
    if os.path.exists(MODEL_PATH):
        print("[AI] Loading existing vulnerability model...")
        return joblib.load(MODEL_PATH)

    # ✅ Correct relative path to reach the 'data' folder from ai_core/
    if data_file is None:
        data_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/vuln_data.csv"))

    if not os.path.exists(data_file):
        print(f"[AI] No CSV dataset found at {data_file}. Cannot train model.")
        return None

    print(f"[AI] Training new model from {data_file}...")

    # Load CSV
    df = pd.read_csv(data_file)

    # Encode service and version as numerical values
    df['service_enc'] = df['service'].astype('category').cat.codes
    df['version_enc'] = df['version'].astype('category').cat.codes

    # Input features and output label
    X = df[['port', 'service_enc', 'version_enc']].values
    y = df['label'].astype('category').cat.codes  # encode labels numerically

    # Split and train
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    # Accuracy evaluation
    score = model.score(X_test, y_test)
    print(f"[AI] Model training complete. Validation accuracy ~ {score:.2f}")

    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"[AI] Model saved to {MODEL_PATH}")

    return model

def classify_vulnerabilities(model, recon_data: dict):
    """
    Predict potential vulnerabilities from recon data using the trained model.
    Returns a list of tuples: (port, service, version, predicted_label_code)
    """
    if model is None:
        print("[AI] No model available. Skipping classification.")
        return []

    open_ports = recon_data.get("open_ports", [])
    predictions = []

    for port_info in open_ports:
        service_name = port_info.get("service", "unknown")
        version_str = port_info.get("version", "0")
        port_num = port_info.get("port", 0)

        service_enc = hash_service(service_name)
        version_enc = hash_version(version_str)

        X_new = np.array([[port_num, service_enc, version_enc]])
        pred_label_code = model.predict(X_new)[0]

        predictions.append((port_num, service_name, version_str, pred_label_code))

    return predictions

def hash_service(service: str) -> int:
    """
    Simple hashing for unknown service labels (fallback if not using trained encodings).
    """
    return abs(hash(service)) % 1000

def hash_version(version: str) -> int:
    return abs(hash(version)) % 1000
