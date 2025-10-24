#!/usr/bin/env python3
"""
evaluate.py
Evaluate a saved model against a labeled CSV file.
Usage:
  python evaluate.py --model model_joblib.pkl --csv ml_features.csv
"""
import argparse, pandas as pd, joblib
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score, confusion_matrix

FEATURE_COLS = [
    "target_sdk","min_sdk","package_len","dangerous_permissions_count","has_hardcoded_secret",
    "exported_components_count","debuggable","api_getDeviceId_count","api_sendSms_count",
    "network_domains_count","domain_entropy","uses_http"
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--csv", required=True)
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    df = df[df['label'].notnull() & (df['label']!='')]
    df['label'] = df['label'].astype(int)
    X = df[FEATURE_COLS]
    y = df['label']

    model = joblib.load(args.model)
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X)[:,1]

    print("Accuracy:", accuracy_score(y, y_pred))
    try:
        print("ROC AUC:", roc_auc_score(y, y_proba))
    except Exception:
        pass
    print("Classification report:\\n", classification_report(y, y_pred))
    print("Confusion matrix:\\n", confusion_matrix(y, y_pred))

if __name__ == "__main__":
    main()
