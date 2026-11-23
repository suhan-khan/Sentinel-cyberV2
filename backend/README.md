# Sentinel Cyber — Backend & Sensor Architecture

FastAPI backend and Windows live network telemetry sensor powering the Sentinel Cyber SOC Dashboard.

---

## 🏗️ Architecture Overview

The backend operates in two primary environments:

```
[ Local Dev ]
  Windows Sensor (windows_monitor.py)
         │  (X-Sentinel-Token)
         ▼
  FastAPI (localhost:8000) ◀────── Browser Frontend (file:// or localhost:3000)
         │
         ▼
  Random Forest Model (artifacts/model.joblib — 74 features)

[ Production ]
  Windows Sensor (Local Machine)
         │  HTTPS + X-Sentinel-Token
         ▼
  Render Backend (https://sentinel-cyber.onrender.com)
         ▲
         │  Public REST (CORS)
  Vercel Frontend (https://sentinel-cyber.vercel.app)
```

---

## 🚀 Local Quickstart

### 1. Install Dependencies

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```

### 3. Start the FastAPI Server

```powershell
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
Interactive Swagger docs: `http://localhost:8000/docs`.

### 4. Start the Windows Live Sensor

In a separate PowerShell terminal:
```powershell
cd backend\sensor
python windows_monitor.py
```
Or double-click `backend\run_sensor.bat`.

---

## 🌐 Production Render Deployment

1. **GitHub Connection**:
   Push this repository to your GitHub account.

2. **Render Web Service Configuration**:
   - **Environment**: Python
   - **Root Directory**: `backend`
   - **Build Command**: `pip install --upgrade pip && pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path**: `/api/health`

3. **Environment Variables on Render**:
   | Variable | Value | Purpose |
   |---|---|---|
   | `PYTHON_VERSION` | `3.11.9` | Ensures compatible Python runtime |
   | `SENTINEL_SENSOR_TOKEN` | `<secure-random-token>` | Secret authentication token for sensor ingest |
   | `CORS_ALLOWED_ORIGINS` | `https://your-app.vercel.app` | Whitelists Vercel frontend domain |
   | `CORS_ALLOW_ALL` | `true` | Allows universal cross-origin requests |
   | `SENTINEL_MAX_UPLOAD_MB` | `50` | Maximum CSV upload size |
   | `SENTINEL_DECISION_THRESHOLD` | `0.05` | Binary classification decision boundary |

4. **Connecting Windows Sensor to Render**:
   On your local machine, set `SENTINEL_API_URL` to your Render URL:
   ```powershell
   python windows_monitor.py --url https://sentinel-cyber.onrender.com --token <YOUR_RENDER_TOKEN>
   ```

---

## 🧠 ML Inference & 74-Feature Flow Requirements

### Model Artifacts (`backend/artifacts/`)
- `model.joblib`: Pre-trained scikit-learn `Pipeline` (containing `SimpleImputer(median)` and `RandomForestClassifier`).
- `feature_columns.json`: 74 ordered statistical network flow features extracted according to CIC-IDS2017 standards.

### Critical Cybersecurity Concept: Host Telemetry vs. Flow Features
- **Host Interface Telemetry (Sensor)**: Measures raw cumulative counters (`psutil`) such as bytes/second, packets/second, and active socket counts (TCP/UDP).
- **ML Flow Classification (Model)**: Requires statistical biflow characteristics aggregated over packet streams (e.g. `Flow Duration`, `Flow IAT Mean`, `Fwd Packet Length Std`, `SYN/FIN Flag Counts`).
- **Safety Guarantee**: The backend deliberately separates host telemetry from model inference. It validates that all 74 flow features exist before running inference, preventing invalid predictions.

---

## 📡 API Endpoints

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | None | System readiness, active ML model, and sensor connection status |
| `GET` | `/api/sensor/telemetry` | None | Sanitized, safe telemetry stream for frontend dashboard |
| `POST` | `/api/sensor/snapshot` | `X-Sentinel-Token` | Authenticated ingest for Windows telemetry sensor |
| `GET` | `/api/sample-dataset` | None | Downloads/registers the 74-feature benchmark dataset (`sample_test.csv`) |
| `POST` | `/api/upload` | None | Uploads and validates network traffic CSV captures |
| `POST` | `/api/predict` | None | Executes Random Forest inference on uploaded dataset ID |
| `GET` | `/api/history` | None | Retrieves historical intrusion analysis sessions |
| `GET` | `/api/analytics` | None | Returns aggregated SOC metrics and threat distributions |
