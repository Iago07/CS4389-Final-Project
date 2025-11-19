#!/usr/bin/env python3
"""
ml_pipeline.py - simple ML tool on top of the framework reports.

There are two main entry points:

1. Train a model from a CSV file of runs:

   $ python ml_pipeline.py train data/runs.csv model.joblib

   The CSV is expected to have at least these columns:
       target, apk_size_mb, num_findings, num_medium_or_high, m1, m2, ..., m10, label

   where:
       - label = 0 for normal runs
       - label = 1 for suspicious or penetration testing like runs

2. Predict from a framework report:

   $ python starter_scan.py some_app.apk
   $ python ml_pipeline.py predict report.json model.joblib
"""

import argparse
import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from joblib import dump, load


FeatureVector = Dict[str, float]


def extract_features_from_report(report_path: Path) -> FeatureVector:
    """
    Turn a framework JSON report into a numeric feature vector.

    We use very simple features for illustration:
      - apk_size_mb: parsed from "Oversized file" result if possible, otherwise 0
      - num_findings: total number of findings
      - num_medium_or_high: count of findings with severity in {medium, high}
      - m1..m10: count of findings in each category M1..M10
    """
    with report_path.open("r", encoding="utf-8") as fp:
        report = json.load(fp)

    findings: List[Dict[str, Any]] = report.get("findings", [])

    num_findings = len(findings)
    num_medium_or_high = sum(
        1 for f in findings if f.get("severity") in {"medium", "high"}
    )

    # Initialize M1..M10 counts
    category_counts = {f"m{i}": 0.0 for i in range(1, 11)}
    apk_size_mb = 0.0

    for f in findings:
        category = f.get("category", "").upper()
        if category.startswith("M"):
            try:
                idx = int(category[1:])
                if 1 <= idx <= 10:
                    category_counts[f"m{idx}"] += 1.0
            except ValueError:
                pass

        if f.get("check") == "Oversized file":
            result = f.get("result", "")
            # crude parsing: look for "<number> MB"
            if "MB" in result:
                try:
                    num_str = result.split("MB")[0].strip().split()[-1]
                    apk_size_mb = float(num_str)
                except Exception:
                    pass

    features: FeatureVector = {
        "apk_size_mb": apk_size_mb,
        "num_findings": float(num_findings),
        "num_medium_or_high": float(num_medium_or_high),
    }
    features.update(category_counts)
    return features


def features_to_matrix(
    features: List[FeatureVector],
) -> Tuple[np.ndarray, List[str]]:
    """
    Convert a list of feature dicts into a feature matrix X and
    a stable, ordered list of feature names.
    """
    if not features:
        raise ValueError("No features provided")

    # Fixed order so training and prediction match
    base_order = [
        "apk_size_mb",
        "num_findings",
        "num_medium_or_high",
    ]
    m_order = [f"m{i}" for i in range(1, 11)]
    feature_names = base_order + m_order

    X = np.array(
        [[f.get(name, 0.0) for name in feature_names] for f in features],
        dtype=float,
    )
    return X, feature_names


def cmd_predict(report_path: Path, model_path: Path) -> None:
    if not model_path.exists():
        raise SystemExit(f"Model file {model_path} not found")

    features = extract_features_from_report(report_path)
    X, feature_names = features_to_matrix([features])

    model_bundle = load(model_path)
    model: LogisticRegression = model_bundle["model"]
    stored_feature_names: List[str] = model_bundle["feature_names"]

    if feature_names != stored_feature_names:
        raise SystemExit("Feature name mismatch between training and prediction")

    y_pred = model.predict(X)[0]
    y_prob = model.predict_proba(X)[0, 1]

    label = "suspicious (pen-test like)" if y_pred == 1 else "normal usage"
    print(f"[*] Classification result: {label}")
    print(f"[*] Suspicious probability: {y_prob:.3f}")


def cmd_train(csv_path: Path, model_out: Path) -> None:
    if not csv_path.exists():
        raise SystemExit(f"Training CSV {csv_path} not found")

    df = pd.read_csv(csv_path)

    # Expected columns
    base_cols = [
        "apk_size_mb",
        "num_findings",
        "num_medium_or_high",
    ]
    m_cols = [f"m{i}" for i in range(1, 11)]
    label_col = "label"

    missing = [c for c in base_cols + m_cols + [label_col] if c not in df.columns]
    if missing:
        raise SystemExit(f"Missing required columns in CSV: {missing}")

    feature_names = base_cols + m_cols
    X = df[feature_names].values.astype(float)
    y = df[label_col].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("[*] Evaluation on held out test set")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, digits=3))

    bundle = {
        "model": model,
        "feature_names": feature_names,
    }
    dump(bundle, model_out)
    print(f"[+] Trained model saved to {model_out}")


def parse_cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple ML pipeline for penetration testing behavior detection."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Train subcommand
    train_p = subparsers.add_parser("train", help="Train a classifier from CSV")
    train_p.add_argument("csv", type=Path, help="Path to labeled CSV dataset")
    train_p.add_argument("model_out", type=Path, help="Output path for model.joblib")

    # Predict subcommand
    pred_p = subparsers.add_parser("predict", help="Classify a single report.json")
    pred_p.add_argument("report", type=Path, help="Path to framework report.json")
    pred_p.add_argument("model", type=Path, help="Path to trained model.joblib")

    return parser.parse_args()


def main() -> None:
    args = parse_cli()
    if args.command == "train":
        cmd_train(args.csv, args.model_out)
    elif args.command == "predict":
        cmd_predict(args.report, args.model)
    else:
        raise SystemExit("Unknown command")


if __name__ == "__main__":
    main()
