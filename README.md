# Sentinel Cyber V2 — AI-Powered Security Operations Center (SOC)

![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-Random%20Forest-F7931E?logo=scikit-learn)
![Frontend](https://img.shields.io/badge/Frontend-HTML%20%7C%20CSS%20%7C%20JavaScript-orange)
![Deployment](https://img.shields.io/badge/Deployment-Vercel%20%7C%20Render-3B82F6)

**Sentinel Cyber V2** is a web-based Security Operations Center (SOC) dashboard designed to monitor network activity, visualize security telemetry, and support machine-learning-based network intrusion detection.

The project combines a responsive cybersecurity dashboard, a FastAPI backend, a Windows host telemetry sensor, and a pre-trained Random Forest model based on the CIC-IDS2017 feature schema.

The current implementation supports live host-level network telemetry from a connected Windows machine. Real-time packet-level flow extraction and live ML inference are planned development milestones.

## 🚀 Live Deployment

- **Frontend:** https://sentinel-cyber-v2-backend.vercel.app/
- **Backend:** https://sentinel-cyber-backend-jntd.onrender.com

The frontend communicates with the deployed FastAPI backend to retrieve sensor telemetry and backend health information.

## 🛡️ Features

### SOC Dashboard
- Dark navy cybersecurity interface with electric-blue accents.
- Responsive dashboard layout and navigation.
- Network activity visualizations using Chart.js.
- KPI cards, telemetry summaries, and dashboard notifications.
- Overview of backend and sensor connectivity.

### Windows Host Telemetry
- Python-based Windows monitoring sensor using `psutil`.
- Collects network interface counters and host-level socket statistics.
- Reports upload/download rates, bytes transferred, packet counters, and TCP/UDP connection information.
- Sends telemetry to the FastAPI backend.
- Displays sensor connectivity and telemetry freshness.

### Backend API
- FastAPI-based REST backend.
- Health-check endpoint.
- Sensor telemetry endpoint.
- Backend integration with the deployed frontend.
- Sensor authentication configuration through environment variables.

### Machine Learning
- Pre-trained Random Forest pipeline.
- CIC-IDS2017 dataset feature schema containing 74 ordered features.
- Model artifact and feature-column metadata.
- Dataset-based prediction workflow.

**Important:** The trained model and dataset prediction workflow are separate from the current host telemetry stream. Host interface counters are not equivalent to the 74 network-flow features expected by the model.

### Dataset Analysis
- CSV dataset ingestion and inspection.
- Feature validation.
- Dataset-based model predictions.
- Prediction history and result visualization.

## 🏗️ System Architecture

```text
                  SENTINEL CYBER V2

       Windows Laptop
             |
             v
     Windows Monitor Sensor
          (psutil)
             |
             v
       HTTPS Telemetry
             |
             v
       FastAPI Backend
           (Render)
             |
             v
       Telemetry API
             |
             v
       SOC Dashboard
           (Vercel)
             |
             v
       Live Monitoring UI
```

The machine-learning pipeline currently operates separately through dataset-based prediction.

## 🧠 Machine Learning Architecture

The project includes a Random Forest classification pipeline trained using the CIC-IDS2017 feature schema.

- Model: Random Forest Classifier
- Feature schema: 74 ordered numerical features
- Dataset: CIC-IDS2017
- Pipeline: Preprocessing and classification
- Model artifact: `model.joblib`
- Feature metadata: `feature_columns.json`

### Host Telemetry vs. Network Flow Classification

These are two different data sources:

| Component | Data collected | Purpose |
|---|---|---|
| Windows host sensor | Interface counters and socket statistics | Live host monitoring |
| CIC-IDS2017 model | 74 network-flow features | Dataset-based intrusion classification |

A host-level upload speed or connection count cannot be substituted for packet-level flow features. Live network-flow inference requires a separate flow-capture and feature-extraction pipeline.

## 🧰 Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | HTML5, CSS3, JavaScript |
| Visualization | Chart.js |
| Backend | Python, FastAPI |
| Machine Learning | Scikit-learn, Random Forest |
| Data Processing | Pandas, NumPy |
| Host Monitoring | psutil |
| Deployment | Vercel, Render |
| Version Control | Git, GitHub |

## 📁 Repository Structure

```text
sentinel-cyber/
├── index.html
├── vercel.json
├── render.yaml
├── .env.example
├── .gitignore
│
├── css/
│   ├── style.css
│   ├── dashboard.css
│   └── responsive.css
│
├── js/
│   ├── api.js
│   ├── app.js
│   ├── dashboard.js
│   ├── upload.js
│   ├── predictions.js
│   ├── charts.js
│   ├── navigation.js
│   └── demo-data.js
│
└── backend/
    ├── main.py
    ├── requirements.txt
    ├── run.bat
    ├── run_sensor.bat
    ├── run.sh
    ├── sample_test.csv
    │
    ├── artifacts/
    │   ├── model.joblib
    │   └── feature_columns.json
    │
    └── sensor/
        ├── windows_monitor.py
        └── __init__.py
```

*This structure describes the expected project layout; update it if the repository structure changes.*

## ⚡ Local Setup

### 1. Clone the repository

```powershell
git clone https://github.com/suhan-khan/Sentinel-cyberV2.git
cd Sentinel-cyberV2
```

### 2. Set up the Python environment

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Start the backend

```powershell
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Backend API documentation:

http://127.0.0.1:8000/docs

### 4. Configure the Windows sensor

Configure the sensor environment variables in PowerShell:

```powershell
$env:SENTINEL_SENSOR_TOKEN = "YOUR_SENSOR_TOKEN"
$env:SENTINEL_API_URL = "http://127.0.0.1:8000"
```

Start the sensor from the repository root:

```powershell
python backend/sensor/windows_monitor.py
```

Keep the sensor terminal running while monitoring.

### 5. Open the frontend

Open `index.html` in a browser or use a local development server such as VS Code Live Server.

Make sure the frontend API configuration points to your local backend.

## ☁️ Cloud Deployment

### Backend — Render

The backend is deployed on Render.

Production API base URL:

```text
https://sentinel-cyber-backend-jntd.onrender.com
```

Configure the required environment variables in the Render dashboard, including the sensor authentication token.

### Frontend — Vercel

The frontend is deployed on Vercel.

Production URL:

```text
https://sentinel-cyber-v2-backend.vercel.app/
```

The frontend must use the correct Render API base URL to retrieve live telemetry.

### Connect a Windows Sensor to the Deployed Backend

Configure the environment variables in PowerShell:

```powershell
$env:SENTINEL_SENSOR_TOKEN = "YOUR_SENSOR_TOKEN"
$env:SENTINEL_API_URL = "https://sentinel-cyber-backend-jntd.onrender.com"
```

Then run:

```powershell
python backend/sensor/windows_monitor.py
```

**Security note:** Never commit real sensor tokens, API credentials, or private environment files to GitHub.

## 🔭 Development Roadmap

The following capabilities are planned or under development:

- [x] SOC frontend deployment
- [x] FastAPI backend deployment
- [x] Windows host telemetry integration
- [x] Live telemetry display
- [x] Random Forest model artifact and 74-feature schema
- [x] Dataset-based prediction workflow
- [ ] Individual network-flow capture
- [ ] Bidirectional flow tracking
- [ ] CIC-IDS2017-compatible 74-feature extraction
- [ ] Live network-flow inference
- [ ] Real-time threat classification and alert generation
- [ ] Multi-device sensor registration and monitoring
- [ ] End-to-end live intrusion detection testing

## ⚠️ Current Limitations

- Live sensor telemetry currently represents host-level network interface statistics.
- The sensor does not yet provide the 74-feature bidirectional network flows required for live Random Forest inference.
- Opening the public dashboard on another computer does not automatically install or start a sensor on that computer.
- Multi-device monitoring is a future development goal.
- Live intrusion detection performance has not yet been validated end to end.

## 📄 License

MIT License.

Developed as a cybersecurity and machine-learning project exploring SOC dashboards, host telemetry monitoring, and network intrusion detection.