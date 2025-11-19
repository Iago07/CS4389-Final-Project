CS 4389 – Final Project

This project implements a simplified mobile application penetration testing framework and a machine learning behavior detection tool. It enables security testers and students to scan Android APK files and classify whether the interaction resembles normal usage or penetration-testing-like behavior.
----------------------------------------------------
Framework Overview 
The framework is implemented in starter_scan.py.
It:

Accepts APK file input

Performs simple preliminary security checks

Categorizes findings using OWASP Mobile Top 10 categories (M1–M10 placeholders)

Outputs results into report.json for ML analysis

Findings include:

Check Type	Example Checks Included
File-based	File extension, file size
Security placeholder categories	M1, M5, M9 mapped alerts

This design makes the framework extensible for future static/dynamic analysis tools.

--------------------------------------------------------

Machine Learning Component
Implemented in ml_pipeline.py.

It extracts numerical features from report.json:

File size

Number of findings

Severity counts

Count of M1–M10 occurrences

Model used:

Logistic Regression

70/30 train-test split

Metrics printed: accuracy, F1-score, confusion matrix

Outputs:

Classification:

normal usage

suspicious (pen-test like)

Probability score

Model file saved as:

model.joblib

---------------------------------------------------

How to run the project
Create Virtual Environment 
python -m venv venv
source venv/bin/activate         # Mac/Linux
venv\Scripts\activate            # Windows

Install Dependencies
pip install numpy pandas scikit-learn joblib

Scan an APK
python starter_scan.py MyTestApp.apk


This generates:

report.json

Train the ML Model

Ensure data/runs.csv exists, then run:

python ml_pipeline.py train data/runs.csv model.joblib

Predict Behavior Classification
python ml_pipeline.py predict report.json model.joblib


Example output:

[*] Classification result: suspicious (pen-test like)
[*] Suspicious probability: 0.842

References

OWASP Mobile Security Testing Guide

Android Developer Documentation

Scikit-Learn Documentation

