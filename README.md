# Sentinel Cyber — AI-Powered Security Operations Center (SOC) & NIDS

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E.svg?logo=scikit-learn)](https://scikit-learn.org)
[![Theme](https://img.shields.io/badge/Theme-Dark%20Navy%20%26%20Electric%20Blue-00E5FF.svg)](#)
[![Deployment](https://img.shields.io/badge/Deploy-Render%20%7C%20Vercel-3B82F6.svg)](#)

Sentinel Cyber is an enterprise-grade Security Operations Center (SOC) dashboard and AI-based Network Intrusion Detection System (NIDS). It integrates live host interface telemetry with a pre-trained Random Forest model trained on the CIC-IDS2017 benchmark dataset to identify malicious ingress vectors (DoS, DDoS, Port Probing, Brute Force Authentication, and Exploits).

---

## 🛡️ Key Features

- **Professional SOC Dashboard Theme**:
  - Engineered with a deep navy palette (`#070B14`, `#10192E`), electric blue accents (`#3B82F6`), and cyber cyan glow (`#00E5FF`).
  - High-contrast responsive data tables, KPI metrics with CSS animations, and Chart.js telemetry visualizations.
- **Dual-Environment Architecture (Localhost & Render)**:
  - **Local Development**: Seamlessly connects to `http://localhost:8000` when running locally or via `file://`.
  - **Production Deployment**: Connects to the Render HTTPS backend (`https://sentinel-cyber.onrender.com`) when deployed on Vercel.
  - Zero hardcoded domain lock-in with one-click environment presets in Settings.
- **Live Windows Host Telemetry**:
  - Live sensor daemon (`windows_monitor.py`) streams interface counters and active sockets (TCP, UDP, Established) to the backend.
  - Public, sanitized telemetry endpoint (`GET /api/sensor/telemetry`) enables frontend display without exposing authentication tokens.
  - Automatic staleness detection flags disconnected sensors (>15s warning, >60s offline).
- **Trained 74-Feature Random Forest Model (CIC-IDS2017)**:
  - Production-grade ML pipeline with `SimpleImputer` and `RandomForestClassifier`.
  - Rigorous input schema validation prevents bandwidth statistics from corrupting flow-level inference.
  - Includes a one-click benchmark dataset loader (`sample_test.csv`) to test real ML predictions instantly.
- **Persistent Audit History & Telemetry Analytics**:
  - Records session history across audits with classification metrics and threat rates.
  - Exportable and filterable results tables with client-side pagination.

---

## 📁 Repository Structure

```
sentinel-cyber/
├── index.html                           # Single-Page Application SOC Interface
├── vercel.json                          # Vercel Production Deployment Config
├── render.yaml                          # Render Blueprint Infrastructure-as-Code
├── .env.example                         # Master Multi-Environment Guide
├── .gitignore                           # Git Rules (excludes virtualenvs, secrets)
│
├── css/
│   ├── style.css                        # Dark Navy Base Theme, Utilities & Glows
│   ├── dashboard.css                    # SOC Cards, Telemetry Banner, Tables & Dropzone
│   └── responsive.css                   # Responsive Layout Breakpoints
│
├── js/
│   ├── api.js                           # Dual-Environment API Adapter & Demo Fallback
│   ├── app.js                           # SPA Orchestrator, Settings & Notifications
│   ├── dashboard.js                     # Overview KPIs, Telemetry Poller & Alert Feed
│   ├── upload.js                        # CSV Ingestion, Validation & Benchmark Loader
│   ├── predictions.js                   # ML Predictions Table, Filtering & History
│   ├── charts.js                        # Chart.js Electric Blue Theme Visualizations
│   ├── navigation.js                    # Sidebar Drawer & Mobile Navigation
│   └── demo-data.js                     # High-Fidelity Synthetic Telemetry
│
├── backend/
│   ├── main.py                          # FastAPI SOC REST API
│   ├── requirements.txt                 # Backend Python Dependencies
│   ├── run.bat                          # One-Click Windows FastAPI Runner
│   ├── run_sensor.bat                   # One-Click Windows Sensor Runner
│   ├── run.sh                           # Linux/macOS Startup Script
│   ├── sample_test.csv                  # Compliant 74-Feature Benchmark Capture
│   │
│   ├── artifacts/
│   │   ├── model.joblib                 # Trained Random Forest Pipeline
│   │   └── feature_columns.json         # 74 Ordered CIC-IDS2017 Feature Names
│   │
│   └── sensor/
│       ├── windows_monitor.py           # Windows Host Telemetry Sensor (psutil)
│       └── __init__.py
```

---

## ⚡ Quick Start (Local Development)

### 1. Start the FastAPI Backend
```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
API Documentation will be available at `http://localhost:8000/docs`.

### 2. Launch the Windows Telemetry Sensor
Open a second PowerShell terminal:
```powershell
cd backend\sensor
python windows_monitor.py
```
Or double-click `backend\run_sensor.bat`.

### 3. Open the Frontend
Open `index.html` in your web browser (or serve with `npx serve` / Live Server). The dashboard automatically detects `localhost` and connects to your local FastAPI instance!

---

## 🚀 Cloud Deployment (Render & Vercel)

### Deploy Backend to Render
1. Push this repository to GitHub.
2. In Render, create a new **Web Service** pointing to your repository.
3. Configure the service:
   - **Root Directory**: `backend`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Set Environment Variables on Render:
   - `PYTHON_VERSION`: `3.11.9`
   - `SENTINEL_SENSOR_TOKEN`: `<your-random-token>`
   - `CORS_ALLOW_ALL`: `true`

### Deploy Frontend to Vercel
1. Import this repository into Vercel.
2. Vercel automatically reads `vercel.json`.
3. In `js/api.js` or via the **Settings** page in the dashboard, set your Render API URL.

### Connect Windows Sensor to Render
To stream your local machine's telemetry directly to the deployed Render backend:
```powershell
python backend\sensor\windows_monitor.py --url https://your-backend.onrender.com --token <YOUR_RENDER_TOKEN>
```

---

## 🔬 Cybersecurity Architecture Note: Host Telemetry vs. Flow Inference

Sentinel Cyber strictly enforces separation between **host-level telemetry** and **network flow classification**:

| Level | Component | Data Source | Features |
|---|---|---|---|
| **Host Interface** | Windows Sensor (`psutil`) | Network Adapter Counters | Bytes/sec, Packets/sec, Socket counts (TCP/UDP) |
| **Network Flow** | Random Forest (`model.joblib`) | Bidirectional Flow Packets | 74 Statistical Flow Features (Duration, IAT, Flags, Packet Lengths) |

> ⚠️ **Important**: Basic interface bandwidth counters cannot be fed directly into a 74-feature CIC-IDS2017 machine learning model. Doing so would produce fabricated or invalid predictions. Genuine real-time flow inference requires a packet-sniffing engine (e.g. Npcap + NFStream/CICFlowMeter) to reconstruct raw biflows.

---

## 📄 License
MIT License. Created for Network Intrusion Detection System research and SOC demonstration.
