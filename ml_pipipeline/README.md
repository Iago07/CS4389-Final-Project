# ML Pipeline for Mobile Pentest Framework

This folder contains scripts to extract features from MobSF JSON reports and static scan outputs,
train a basic ML model, evaluate it, and serve predictions via a Flask API.

## Files
- `extract_features.py` : parse MobSF `report.json` and optional `strings_found.txt` and apktool decompiled dir -> append row to `ml_features.csv`
- `train.py` : train a sklearn pipeline (StandardScaler + RandomForest) and save model
- `evaluate.py` : evaluate a saved model against a labeled CSV
- `predict_api.py` : Flask API to load the model and return malicious probability
- `requirements.txt` : Python requirements

## Quick setup (VS Code)

1. Open the project folder in VS Code.
2. Create a Python virtual environment (recommended):
   - Windows (PowerShell):
     ```powershell
     python -m venv .venv
     .\\.venv\\Scripts\\Activate.ps1
     pip install --upgrade pip
     pip install -r requirements.txt
     ```
   - Windows (cmd):
     ```cmd
     python -m venv .venv
     .\\.venv\\Scripts\\activate.bat
     pip install -r requirements.txt
     ```
   - macOS / Linux:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     pip install -r requirements.txt
     ```

3. Using VS Code, open the command palette (Ctrl+Shift+P) -> "Python: Select Interpreter" -> choose the `.venv` you created.
4. To extract features from a MobSF report:
   ```bash
   python extract_features.py --mobsf path/to/report.json --strings path/to/strings_found.txt --apktool path/to/apktool_dir --out ml_features.csv --label 1
   ```
   Repeat for multiple apps (use label=0 for benign, 1 for malicious) to build a dataset.
5. Train the model:
   ```bash
   python train.py --csv ml_features.csv --out model_joblib.pkl
   ```
6. Evaluate the model:
   ```bash
   python evaluate.py --model model_joblib.pkl --csv ml_features.csv
   ```
7. Run the prediction API (after training):
   ```bash
   python predict_api.py --model model_joblib.pkl --host 127.0.0.1 --port 5000
   ```
   Example request:
   ```bash
   curl -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" -d '{"target_sdk":29,"min_sdk":21,"package_len":20,"dangerous_permissions_count":3,"has_hardcoded_secret":0,"exported_components_count":1,"debuggable":0,"api_getDeviceId_count":0,"api_sendSms_count":0,"network_domains_count":2,"domain_entropy":1.5,"uses_http":0}'
   ```

## Notes and next steps
- Improve feature extraction by parsing more fields from MobSF such as API strings, network endpoints, intent filters, and crypto usage.
- Use dynamic logs (Frida output) to add runtime features.
- Balance your dataset and consider cross-validation for robust evaluation.
