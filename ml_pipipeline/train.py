#!/usr/bin/env python3
"""
train.py
Train a sklearn pipeline (StandardScaler + RandomForest) on ml_features.csv and save the model.
Usage:
  python train.py --csv ml_features.csv --out model_joblib.pkl
"""
import argparse, pandas as pd, joblib, os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

FEATURE_COLS = [
    "target_sdk","min_sdk","package_len","dangerous_permissions_count","has_hardcoded_secret",
    "exported_components_count","debuggable","api_getDeviceId_count","api_sendSms_count",
    "network_domains_count","domain_entropy","uses_http"
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Input CSV with features")
    parser.add_argument("--out", default="model_joblib.pkl", help="Output model path")
    parser.add_argument("--test_size", type=float, default=0.25)
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    # drop rows with empty label
    df = df[df['label'].notnull() & (df['label']!='')]
    df['label'] = df['label'].astype(int)
    X = df[FEATURE_COLS]
    y = df['label']

    # Basic train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size, random_state=42, stratify=y)

    pipeline = Pipeline([('scaler', StandardScaler()), ('rf', RandomForestClassifier(n_estimators=200, random_state=42))])
    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:,1]

    print("Accuracy:", accuracy_score(y_test, y_pred))
    try:
        print("ROC AUC:", roc_auc_score(y_test, y_proba))
    except Exception:
        pass
    print("Classification report:\\n", classification_report(y_test, y_pred))

    # Cross-val score (optional)
    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring='accuracy')
    print("Cross-val accuracy (5-fold):", cv_scores.mean(), cv_scores)

    joblib.dump(pipeline, args.out)
    print("Saved model to", args.out)

if __name__ == "__main__":
    main()
