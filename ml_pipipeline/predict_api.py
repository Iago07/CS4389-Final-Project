#!/usr/bin/env python3
"""
predict_api.py
Simple Flask API that loads the trained model and returns a probability for incoming feature JSON.

Usage:
  python predict_api.py --model model_joblib.pkl --host 0.0.0.0 --port 5000
POST /predict  JSON body: {"target_sdk":29, "min_sdk":21, ... } -> returns {"malicious_prob":0.87}
"""
import argparse, joblib, json
from flask import Flask, request, jsonify
import numpy as np

FEATURE_COLS = [
    "target_sdk","min_sdk","package_len","dangerous_permissions_count","has_hardcoded_secret",
    "exported_components_count","debuggable","api_getDeviceId_count","api_sendSms_count",
    "network_domains_count","domain_entropy","uses_http"
]

app = Flask(__name__)
model = None

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    # expect either a single sample dict or list of dicts
    if isinstance(data, dict):
        samples = [data]
    else:
        samples = data
    X = []
    for s in samples:
        row = [s.get(c,0) for c in FEATURE_COLS]
        X.append(row)
    X = np.array(X)
    probs = model.predict_proba(X)[:,1].tolist()
    return jsonify({"malicious_prob": probs})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    model = joblib.load(args.model)
    print("Loaded model:", args.model)
    app.run(host=args.host, port=args.port)
