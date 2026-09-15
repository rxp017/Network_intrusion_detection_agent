# 🛡️ NIDA: Network Intrusion Detection Agent & SOC Dashboard

NIDA is a hybrid Network Intrusion Detection System (NIDS) powered by machine learning and real-time streaming telemetry. It bridges the gap between traditional rule-based firewalls and modern SIEM security analytics by detecting both **known cyberattack categories** and novel **zero-day anomalies**.

---

## 🚀 Quick Start (Run in 2 Steps)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Application
```bash
python main.py
```

Open your browser at **[http://localhost:8000](http://localhost:8000)**.
The live SOC dashboard will automatically connect, start streaming network flow telemetry, display real-time attack classifications, calculate composite risk scores, and render explainability metrics.

---

## 🧠 How NIDA Works: Simple & Detailed Explanation

### The Problem
Traditional intrusion detection relies on signature matching (like antivirus definitions). If an attacker modifies their malware slightly or uses a previously unseen technique (a **zero-day exploit**), signatures fail completely. Conversely, pure anomaly detectors flag anything unusual, flooding security teams with false alarms.

### NIDA's Hybrid Dual-Engine Architecture
NIDA solves this by running two specialized ML models in parallel on every incoming network flow:

```
                  ┌─────────────────────────────────────────┐
                  │       Incoming Network Flow Event       │
                  │   (42 NetFlow features: TTL, bytes...)  │
                  └────────────────────┬────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │   Supervised Engine   │             │  Unsupervised Engine  │
        │        XGBoost        │             │   Isolation Forest    │
        │                       │             │                       │
        │ Predicts Attack Class │             │  Trained EXCLUSIVELY  │
        │ (DoS, Exploits, etc.) │             │   on Benign Traffic   │
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    │ Predicted Class                     │ Anomaly Score
                    │ & Probability Confidence            │ (-1 outlier to +1 normal)
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                   ┌───────────────────────────────────────┐
                   │       Composite Risk Scorer           │
                   │                                       │
                   │ • Zero-Day Flag: Normal + Anomaly     │
                   │ • Risk Score: 0 - 100 Scale           │
                   │ • Tiers: Low / Medium / High / Crit   │
                   └───────────────────┬───────────────────┘
                                       ▼
                   ┌───────────────────────────────────────┐
                   │    Live WebSocket Stream (Port 8000)  │
                   │       Interactive SOC Dashboard       │
                   └───────────────────────────────────────┘
```

1. **Supervised Classifier (XGBoost)**:
   - Trained across 10 network traffic classes from the **UNSW-NB15** dataset (`Normal`, `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`).
   - Identifies specific attack behaviors and outputs prediction probabilities.

2. **Unsupervised Anomaly Detector (Isolation Forest)**:
   - Fitted **strictly on verified benign (normal) traffic**.
   - Learns the multidimensional boundary of healthy network communication.
   - Evaluates how hard it is to isolate a given packet. High isolation ease = anomalous packet structure.

3. **Zero-Day Detection Heuristic**:
   - When XGBoost classifies an event as **"Normal"**, BUT the Isolation Forest scores it as an extreme structural outlier (normalized anomaly score $\ge 0.75$), NIDA flags it with a **`⚠️ ZERO-DAY?`** alert.
   - This catches unseen exploits designed to bypass signature and supervised classifiers.

4. **Composite Risk Score (0–100)**:
   - Combines the attack probability, severity weight of the attack class, and anomaly magnitude.
   - Categorized into clear security operational tiers: `Low`, `Medium`, `High`, and `Critical`.

---

## 🖥️ The Interactive SOC Dashboard

When you open `http://localhost:8000`, you see:

- **HUD Status Counters**: Real-time counter of total packets inspected, attacks detected, critical severity threats, and zero-day alerts.
- **Live NetFlow Telemetry Table**: Real-time log of the latest 30 network flows, color-coded by threat tier.
- **Attack Category Bar Chart**: Dynamically animated Chart.js breakdown showing real-time distribution of detected attack vectors.
- **Explainability Drawer (XAI)**: Click **any row** in the live table to inspect *why* the model made that prediction. The drawer queries `/explain/{attack_cat}` and displays the top feature importances and anomaly parameters for that flow.
- **Dataset Transparency Banner**: Clearly warns analysts about rare attack classes with low training support (e.g., Worms with 44 samples), adhering to modern AI safety standards.

---

## 📁 Repository Structure

```
.
├── artifacts/                  # Serialized models and metadata
│   ├── classifier.pkl          # Trained XGBoost multiclass model
│   ├── isoforest.pkl           # Trained Isolation Forest model
│   ├── scaler.pkl              # RobustScaler fitted on training data
│   ├── label_encoder.pkl       # Target encoder for attack classes
│   ├── columns.json            # Categorical column mappings
│   ├── numeric_columns.json    # Standardized numeric feature list
│   ├── anomaly_bounds.json     # Min/max bounds for score normalization
│   ├── class_report.json       # Per-class precision, recall, F1 metrics
│   ├── explainability.json     # Precomputed global feature importances
│   └── limitations.json        # Class imbalance and calibration audit
├── dashboard.html              # Modern, responsive single-page SOC dashboard
├── generate_sample_data.py     # Script to generate benchmark sample sets
├── main.py                     # FastAPI server with WebSocket streaming & REST API
├── model.py                    # ModelBundle inference pipeline & feature transformer
├── train.py                    # Complete model training and evaluation pipeline
├── requirements.txt            # Project dependencies
├── UNSW_NB15_training-set.csv  # Training dataset sample
└── UNSW_NB15_testing-set.csv   # Evaluation & live streaming test set
```

---

## 🔌 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Serves the interactive SOC Dashboard (`dashboard.html`) |
| `/dashboard` | `GET` | Direct alias to the SOC Dashboard |
| `/health` | `GET` | Health check endpoint returning status and active attack classes |
| `/predict` | `POST` | Scored single flow record against the dual-engine pipeline |
| `/explain/{attack_cat}` | `GET` | Returns top feature importances for a specific attack category |
| `/limitations` | `GET` | Returns model limitations and low-support class audit |
| `/ws/stream` | `WebSocket` | Real-time WebSocket streaming scored records from the test dataset |

---

## 🔬 Retraining the Models

If you want to train the models from scratch on custom data:

```bash
python train.py
```

This will:
1. Load `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv`.
2. Compute categorical encodings and robust feature scalings.
3. Fit XGBoost and Isolation Forest.
4. Compute per-class precision/recall and anomaly calibration bounds.
5. Export all production artifacts into `./artifacts/`.
