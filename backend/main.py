
from __future__ import annotations

import json
import uuid
import logging
import os
import secrets
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from fastapi import (
    FastAPI,
    File,
    Header,
    HTTPException,
    UploadFile,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError

# --------------------------------------------------
# ENVIRONMENT & DIRECTORIES
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
UPLOAD_DIR = BASE_DIR / "uploads"
ARTIFACT_DIR = BASE_DIR / "artifacts"

try:
    from dotenv import load_dotenv

    if (BASE_DIR / ".env").exists():
        load_dotenv(BASE_DIR / ".env")
    elif (PROJECT_ROOT / ".env").exists():
        load_dotenv(PROJECT_ROOT / ".env")

except ImportError:
    pass


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger("sentinel")

MODEL_PATH = ARTIFACT_DIR / "model.joblib"
FEATURES_PATH = ARTIFACT_DIR / "feature_columns.json"

THRESHOLD = float(os.getenv("SENTINEL_DECISION_THRESHOLD", "0.05"))
MAX_UPLOAD_BYTES = int(os.getenv("SENTINEL_MAX_UPLOAD_MB", "50")) * 1024 * 1024
MAX_PREVIEW_ROWS = 8

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------
# FASTAPI APP & CORS
# --------------------------------------------------

app = FastAPI(
    title="Sentinel Cyber API",
    description="AI/ML Network Intrusion Detection API & SOC Telemetry Backend",
    version="2.0.1",
)

cors_env = os.getenv("CORS_ALLOWED_ORIGINS", "")

if cors_env.strip():
    allowed_origins = [
        origin.strip()
        for origin in cors_env.split(",")
        if origin.strip()
    ]
else:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

cors_allow_all = os.getenv("CORS_ALLOW_ALL", "true").lower() == "true"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if cors_allow_all else allowed_origins,
    allow_origin_regex=(
        r"^https:\/\/.*\.vercel\.app$"
        if not cors_allow_all
        else None
    ),
    allow_credentials=False if cors_allow_all else True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# IN-MEMORY STORAGE
# --------------------------------------------------

datasets: dict[str, dict[str, Any]] = {}
history: list[dict[str, Any]] = []
latest_analytics: dict[str, Any] = {}

# --------------------------------------------------
# SENSOR MODELS & TELEMETRY
# --------------------------------------------------

class PredictRequest(BaseModel):
    dataset_id: str


class SensorConnections(BaseModel):
    total: int = Field(ge=0)
    tcp: int = Field(ge=0)
    udp: int = Field(ge=0)
    established: int = Field(ge=0)


class SensorSnapshot(BaseModel):
    timestamp: str = Field(max_length=64)
    device: str = Field(min_length=1, max_length=100)
    interface: str = Field(min_length=1, max_length=100)

    upload_kbps: float = Field(ge=0, le=10_000_000)
    download_kbps: float = Field(ge=0, le=10_000_000)

    bytes_sent_total: int = Field(ge=0)
    bytes_received_total: int = Field(ge=0)

    packets_sent: int = Field(ge=0)
    packets_received: int = Field(ge=0)

    errors_in: int = Field(ge=0)
    errors_out: int = Field(ge=0)

    connections: SensorConnections


SENSOR_TOKEN = os.getenv("SENTINEL_SENSOR_TOKEN", "")

latest_sensor_snapshot: dict[str, Any] | None = None
sensor_history: deque[dict[str, Any]] = deque(maxlen=120)

# --------------------------------------------------
# LIVE FLOW STORAGE
# --------------------------------------------------

live_flow_history: deque[dict[str, Any]] = deque(maxlen=500)

live_flow_stats: dict[str, Any] = {
    "total_flows": 0,
    "normal_flows": 0,
    "malicious_flows": 0,
    "threat_rate": 0.0,
    "avg_confidence": 0.0,
    "last_flow_at": None,
    "capture_method": "none",
}


class FlowMetadata(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: str
    last_seen: str
    total_packets: int
    total_bytes: int


class FlowItem(BaseModel):
    metadata: FlowMetadata
    features: dict[str, Any]


class SensorFlowBatch(BaseModel):
    device: str
    timestamp: str
    capture_method: str = "passive_flow_sniffer"
    flows: list[FlowItem]


# --------------------------------------------------
# MODEL LOADING & CACHING
# --------------------------------------------------

_CACHED_MODEL = None
_CACHED_COLUMNS: list[str] | None = None
_MODEL_LOADED = False


def load_model():
    """Load the trained model and its feature list."""

    logger.info("Checking trained model artifacts...")
    logger.info("Model path: %s", MODEL_PATH)
    logger.info("Features path: %s", FEATURES_PATH)

    if not MODEL_PATH.exists():
        logger.error("Model file not found: %s", MODEL_PATH)
        return None, None

    if not FEATURES_PATH.exists():
        logger.error("Feature file not found: %s", FEATURES_PATH)
        return None, None

    try:
        logger.info("Loading Random Forest model...")

        loaded_obj = joblib.load(MODEL_PATH)

        if isinstance(loaded_obj, dict):
            model = loaded_obj.get("model", loaded_obj)

            global THRESHOLD

            if (
                "threshold" in loaded_obj
                and "SENTINEL_DECISION_THRESHOLD" not in os.environ
            ):
                THRESHOLD = float(loaded_obj["threshold"])

                logger.info(
                    "Using decision threshold from model artifact: %s",
                    THRESHOLD
                )
        else:
            model = loaded_obj

        logger.info("Loading feature columns...")

        columns = json.loads(
            FEATURES_PATH.read_text(encoding="utf-8")
        )

        if not isinstance(columns, list):
            raise ValueError("Feature columns must be a JSON list.")

        if len(columns) != 74:
            raise ValueError(
                f"Expected 74 features, found {len(columns)}."
            )

        if hasattr(model, "n_features_in_"):
            model_features = model.n_features_in_

            if model_features != len(columns):
                raise ValueError(
                    f"Model expects {model_features} features, "
                    f"but feature list contains {len(columns)}."
                )

        if not hasattr(model, "predict_proba"):
            raise ValueError(
                "Model does not support predict_proba()."
            )

        logger.info(
            "Model classes: %s",
            getattr(model, "classes_", "Unknown")
        )

        logger.info("SUCCESS: Random Forest loaded!")

        return model, columns

    except Exception as exc:
        logger.exception(
            "MODEL LOADING FAILED: %s: %s",
            type(exc).__name__,
            exc
        )

        return None, None


def get_cached_model():
    """Retrieve the cached model."""

    global _CACHED_MODEL
    global _CACHED_COLUMNS
    global _MODEL_LOADED

    if not _MODEL_LOADED:
        _CACHED_MODEL, _CACHED_COLUMNS = load_model()
        _MODEL_LOADED = True

    return _CACHED_MODEL, _CACHED_COLUMNS


@app.on_event("startup")
def on_startup():
    """Preload the model during server startup."""

    logger.info("Initializing Sentinel Cyber API backend...")

    get_cached_model()

    if SENSOR_TOKEN:
        logger.info(
            "Sensor authentication enabled with configured token."
        )
    else:
        logger.warning(
            "No SENTINEL_SENSOR_TOKEN configured. "
            "Sensor endpoints will use fallback token in dev mode."
        )


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)

        return result if np.isfinite(result) else default

    except (TypeError, ValueError):
        return default


def first_matching(
    row: pd.Series,
    candidates: list[str],
    fallback: str
) -> str:

    lowered = {
        str(key).strip().lower(): key
        for key in row.index
    }

    for candidate in candidates:
        key = lowered.get(candidate.lower())

        if key is not None and pd.notna(row[key]):
            return str(row[key])

    return fallback


def compute_sensor_age() -> tuple[str, bool, float | None]:
    """Calculate the sensor's online/stale/offline status."""

    if latest_sensor_snapshot is None:
        return "offline", False, None

    try:
        received_str = latest_sensor_snapshot.get(
            "received_at",
            ""
        )

        if received_str:
            received_dt = datetime.fromisoformat(received_str)

            age = max(
                0.0,
                (
                    datetime.now(timezone.utc) - received_dt
                ).total_seconds()
            )

            if age <= 15.0:
                return "online", True, round(age, 1)

            elif age <= 60.0:
                return "stale", True, round(age, 1)

            else:
                return "offline", False, round(age, 1)

    except Exception:
        logger.exception("Could not calculate sensor age.")

    return "offline", False, None


# --------------------------------------------------
# ROOT & SYSTEM HEALTH
# --------------------------------------------------

@app.get("/")
def root():

    return {
        "name": "Sentinel Cyber API",
        "version": "2.0.1",
        "status": "online",
        "docs": "/docs",
        "health": "/api/health",
        "sensor_telemetry": "/api/sensor/telemetry",
    }


@app.get("/api/health")
def health():

    model, columns = get_cached_model()

    ready = model is not None and columns is not None

    sensor_status, sensor_connected, sensor_age = (
        compute_sensor_age()
    )

    sensor_detail = (
        f"Active ({sensor_age}s ago)"
        if sensor_status == "online"
        else f"Stale ({sensor_age}s ago)"
        if sensor_status == "stale"
        else "Disconnected / Offline"
    )

    return {
        "status": "online",

        "model": {
            "status": "online" if ready else "offline",
            "label": "Random Forest",
            "detail": (
                f"Inference ready ({len(columns)} features)"
                if ready
                else "Model loading failed - check artifacts"
            ),
        },

        "api": {
            "status": "online",
            "label": "API Connection",
            "detail": "FastAPI Operational",
        },

        "dataset": {
            "status": "ready",
            "label": "Dataset Processor",
            "detail": "CSV ingestion operational",
        },

        "sensor": {
            "status": sensor_status,
            "connected": sensor_connected,
            "label": "Live Network Sensor",
            "detail": sensor_detail,
            "live_flows_count": live_flow_stats["total_flows"],
            "live_threats_count": live_flow_stats["malicious_flows"],
        },

        "model_ready": ready,
        "feature_count": len(columns) if ready else 0,
        "threshold": THRESHOLD,
        "last_analysis": history[0]["date"] if history else None,
        "live_flows": live_flow_stats,
    }


# --------------------------------------------------
# CSV UPLOAD & SAMPLE DATASET
# --------------------------------------------------

@app.post("/api/upload")
async def upload_dataset(file: UploadFile = File(...)):

    filename = file.filename or "uploaded.csv"

    if Path(filename).suffix.lower() != ".csv":
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are supported."
        )

    content = await file.read(MAX_UPLOAD_BYTES + 1)

    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File exceeds the "
                f"{MAX_UPLOAD_BYTES // (1024 * 1024)}MB upload limit."
            )
        )

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV is empty."
        )

    dataset_id = "DS-" + uuid.uuid4().hex[:10].upper()

    saved_path = UPLOAD_DIR / f"{dataset_id}.csv"

    saved_path.write_bytes(content)

    try:
        frame = pd.read_csv(
            saved_path,
            nrows=MAX_PREVIEW_ROWS + 1
        )

        if frame.empty:
            raise ValueError("CSV contains no data rows.")

        full_frame = pd.read_csv(saved_path)

    except Exception as exc:

        saved_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=400,
            detail=f"Could not read CSV: {exc}"
        ) from exc

    datasets[dataset_id] = {
        "path": saved_path,
        "filename": Path(filename).name,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(full_frame)),
        "columns": list(full_frame.columns),
    }

    return {
        "datasetId": dataset_id,
        "dataset_id": dataset_id,
        "filename": Path(filename).name,
        "size": len(content),
        "status": "uploaded",
        "rows": int(len(full_frame)),
        "columns": list(full_frame.columns),
        "preview": (
            frame.head(MAX_PREVIEW_ROWS)
            .replace({np.nan: None})
            .to_dict(orient="records")
        ),
    }


@app.get("/api/sample-dataset")
def get_sample_dataset():

    sample_file = BASE_DIR / "sample_test.csv"

    if not sample_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Sample dataset not found."
        )

    df = pd.read_csv(sample_file)

    dataset_id = "DS-SAMPLE-CICIDS2017"

    datasets[dataset_id] = {
        "path": sample_file,
        "filename": "sample_test.csv",
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(df)),
        "columns": list(df.columns),
    }

    return {
        "datasetId": dataset_id,
        "dataset_id": dataset_id,
        "filename": "sample_test.csv",
        "size": sample_file.stat().st_size,
        "rows": int(len(df)),
        "columns": list(df.columns),
        "preview": (
            df.head(MAX_PREVIEW_ROWS)
            .replace({np.nan: None})
            .to_dict(orient="records")
        ),
        "status": "ready",
    }


# --------------------------------------------------
# PREDICTION - GENUINE ML INFERENCE
# --------------------------------------------------

@app.post("/api/predict")
def predict(request: PredictRequest):

    dataset = datasets.get(request.dataset_id)

    if not dataset:
        raise HTTPException(
            status_code=404,
            detail="Dataset ID not found. Upload the CSV again."
        )

    model, feature_columns = get_cached_model()

    if model is None or feature_columns is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Trained ML model is not available. "
                "Ensure artifacts/model.joblib is installed."
            )
        )

    try:
        frame = pd.read_csv(dataset["path"])

        csv_col_clean = {
            str(column).strip(): column
            for column in frame.columns
        }

        missing = [
            column
            for column in feature_columns
            if column not in frame.columns
            and column not in csv_col_clean
        ]

        if missing:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": (
                        "CSV dataset is missing required "
                        "CIC-IDS2017 model features."
                    ),
                    "missing_columns": missing,
                    "expected_count": len(feature_columns),
                    "note": (
                        "The Random Forest model requires 74 "
                        "bidirectional network flow statistics. "
                        "Host interface bandwidth statistics "
                        "cannot be used for flow inference."
                    ),
                },
            )

        mapped_cols = [
            column
            if column in frame.columns
            else csv_col_clean[column]
            for column in feature_columns
        ]

        X = frame[mapped_cols].copy()
        X.columns = feature_columns

        for column in X.columns:
            X[column] = pd.to_numeric(
                X[column],
                errors="coerce"
            )

        X = X.replace(
            [np.inf, -np.inf],
            np.nan
        )

        probabilities = model.predict_proba(X)

        classes = list(model.classes_)

        if 1 not in classes:
            raise ValueError(
                f"Attack class 1 not found in model classes: {classes}"
            )

        attack_index = classes.index(1)

        attack_probabilities = probabilities[:, attack_index]

        predictions_binary = (
            attack_probabilities >= THRESHOLD
        ).astype(int)

        predictions = []

        for index, (_, row) in enumerate(frame.iterrows()):

            is_attack = bool(predictions_binary[index])

            attack_prob = safe_float(
                attack_probabilities[index]
            )

            confidence = (
                attack_prob
                if is_attack
                else 1.0 - attack_prob
            )

            classification = (
                "ATTACK"
                if is_attack
                else "BENIGN"
            )

            protocol = first_matching(
                row,
                ["Protocol", "protocol"],
                "Unknown"
            )

            src_ip = first_matching(
                row,
                ["Source IP", "Src IP", "src_ip", "SourceIP"],
                "N/A"
            )

            dst_ip = first_matching(
                row,
                [
                    "Destination IP",
                    "Dst IP",
                    "dst_ip",
                    "DestinationIP"
                ],
                "N/A"
            )

            severity = (
                "Critical"
                if is_attack and confidence >= 0.90
                else "High"
                if is_attack and confidence >= 0.75
                else "Medium"
                if is_attack
                else "Normal"
            )

            predictions.append({
                "id": index + 1,
                "srcIp": src_ip,
                "dstIp": dst_ip,
                "protocol": protocol,
                "classification": classification,
                "confidence": round(confidence, 4),
                "attackProbability": round(attack_prob, 4),
                "severity": severity,
            })

        total = len(predictions)

        malicious = int(predictions_binary.sum())

        normal = total - malicious

        result = {
            "predictions": predictions,

            "stats": {
                "total": total,
                "normal": normal,
                "malicious": malicious,

                "threatRate": round(
                    (malicious / total) * 100,
                    1
                ) if total > 0 else 0.0,

                "avgConfidence": round(
                    float(
                        np.mean([
                            prediction["confidence"]
                            for prediction in predictions
                        ])
                    ) if predictions else 0.0,
                    4,
                ),
            },
        }

        record = {
            "id": "ANA-" + uuid.uuid4().hex[:8].upper(),
            "filename": dataset["filename"],
            "date": datetime.now(timezone.utc).isoformat(),
            "records": total,
            "malicious": malicious,
            "status": "Completed",
        }

        history.insert(0, record)

        latest_analytics.clear()

        latest_analytics.update(
            build_analytics(predictions)
        )

        return result

    except HTTPException:
        raise

    except Exception as exc:

        logger.exception("Prediction failed")

        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {exc}"
        ) from exc


# --------------------------------------------------
# ANALYTICS & HISTORY
# --------------------------------------------------

def build_analytics(
    predictions: list[dict[str, Any]]
) -> dict[str, Any]:

    total = len(predictions)

    normal = sum(
        prediction["classification"] == "BENIGN"
        for prediction in predictions
    )

    malicious = total - normal

    protocols: dict[str, int] = {}
    attacks: dict[str, int] = {}

    for item in predictions:

        protocol = item.get("protocol", "Unknown")

        protocols[protocol] = (
            protocols.get(protocol, 0) + 1
        )

        if item["classification"] == "ATTACK":

            severity = item.get("severity", "Medium")

            attacks[severity] = (
                attacks.get(severity, 0) + 1
            )

    return {
        "totalConnections": total,
        "maliciousDetected": malicious,
        "normalConnections": normal,

        "detectionRate": round(
            (malicious / total) * 100,
            2
        ) if total else 0,

        "protocolDistribution": protocols,
        "attackDistribution": attacks,

        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/history")
def get_history():
    return history


@app.get("/api/analytics")
def get_analytics():

    return latest_analytics or {
        "totalConnections": 0,
        "maliciousDetected": 0,
        "normalConnections": 0,
        "detectionRate": 0,
        "protocolDistribution": {},
        "attackDistribution": {},
    }


# --------------------------------------------------
# SENSOR AUTHENTICATION
# --------------------------------------------------

def verify_sensor_token(token: str | None) -> None:
    """Validate the Windows sensor authentication token."""

    configured_token = (
        SENSOR_TOKEN
        or "sentinel-local-dev-token"
    )

    if (
        not token
        or not secrets.compare_digest(
            token,
            configured_token
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing sensor authentication token.",
        )


# --------------------------------------------------
# SENSOR SNAPSHOT INGESTION
# --------------------------------------------------

@app.post("/api/sensor/snapshot")
async def receive_sensor_snapshot(
    request: Request,
    x_sentinel_token: str | None = Header(
        default=None,
        alias="X-Sentinel-Token",
    ),
):
    """
    Receive host network telemetry from the Windows sensor.

    The request body is read manually so that malformed JSON
    and individual field validation failures can be diagnosed.
    """

    global latest_sensor_snapshot

    # 1. Authenticate before processing the telemetry.
    verify_sensor_token(x_sentinel_token)

    # 2. Read the raw request body.
    try:
        raw_body = await request.body()

    except Exception:
        logger.exception(
            "Could not read sensor snapshot request body."
        )

        raise HTTPException(
            status_code=400,
            detail="Could not read request body.",
        )

    # 3. Reject an empty request.
    if not raw_body:
        logger.warning(
            "Sensor snapshot rejected: empty request body."
        )

        raise HTTPException(
            status_code=400,
            detail="Empty request body. Expected a JSON sensor snapshot.",
        )

    # 4. Parse JSON explicitly.
    try:
        body_text = raw_body.decode("utf-8")

        snapshot_data = json.loads(body_text)

    except UnicodeDecodeError:
        logger.warning(
            "Sensor snapshot rejected: body is not valid UTF-8."
        )

        raise HTTPException(
            status_code=400,
            detail="Request body must use UTF-8 encoding.",
        )

    except json.JSONDecodeError as exc:
        logger.warning(
            "Sensor snapshot rejected: invalid JSON at line %s column %s.",
            exc.lineno,
            exc.colno,
        )

        raise HTTPException(
            status_code=400,
            detail={
                "message": "Invalid JSON in sensor request.",
                "line": exc.lineno,
                "column": exc.colno,
            },
        )

    # 5. Confirm the JSON root is an object.
    if not isinstance(snapshot_data, dict):

        logger.warning(
            "Sensor snapshot rejected: JSON root is not an object."
        )

        raise HTTPException(
            status_code=400,
            detail="Expected a JSON object for the sensor snapshot.",
        )

    # 6. Validate against the SensorSnapshot model.
    try:
        snapshot = SensorSnapshot.model_validate(
            snapshot_data
        )

    except ValidationError as exc:

        errors = exc.errors(
            include_url=False,
            include_context=False,
            include_input=False,
        )

        logger.warning(
            "Sensor snapshot validation failed: %s",
            json.dumps(errors, default=str),
        )

        raise HTTPException(
            status_code=422,
            detail={
                "message": "Sensor snapshot validation failed.",
                "errors": errors,
                "received_fields": list(snapshot_data.keys()),
            },
        )

    # 7. Save the accepted snapshot.
    received_at = datetime.now(
        timezone.utc
    ).isoformat()

    latest_sensor_snapshot = {
        **snapshot.model_dump(),
        "received_at": received_at,
    }

    sensor_history.append(
        latest_sensor_snapshot
    )

    logger.info(
        "Sensor snapshot accepted | device=%s | interface=%s | "
        "connections=%s | history_count=%s",
        snapshot.device,
        snapshot.interface,
        snapshot.connections.total,
        len(sensor_history),
    )

    return {
        "status": "received",
        "received_at": received_at,
        "history_count": len(sensor_history),
        "device": snapshot.device,
        "interface": snapshot.interface,
    }


# --------------------------------------------------
# PUBLIC SENSOR TELEMETRY
# --------------------------------------------------

@app.get("/api/sensor/telemetry")
def get_sensor_telemetry():

    if latest_sensor_snapshot is None:

        return {
            "status": "offline",
            "connected": False,

            "message": (
                "No sensor telemetry received yet. "
                "Run backend/sensor/windows_monitor.py "
                "on Windows to stream live telemetry."
            ),

            "last_seen": None,
            "age_seconds": None,
            "device": None,
            "interface": None,

            "upload_kbps": 0.0,
            "download_kbps": 0.0,

            "bytes_sent_total": 0,
            "bytes_received_total": 0,

            "packets_sent": 0,
            "packets_received": 0,

            "errors_in": 0,
            "errors_out": 0,

            "connections": {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "established": 0,
            },

            "history": [],
            "history_count": 0,

            "telemetry_type": "host_interface_counters",
            "model_compatible": False,

            "disclaimer": (
                "Host network interface telemetry (psutil). "
                "Distinct from the 74-feature bidirectional "
                "flow records used by the Random Forest model."
            ),
        }

    status, connected, age_seconds = (
        compute_sensor_age()
    )

    history_points = []

    for snap in list(sensor_history)[-30:]:

        history_points.append({
            "timestamp": snap.get("timestamp"),
            "upload_kbps": snap.get("upload_kbps", 0.0),
            "download_kbps": snap.get("download_kbps", 0.0),
            "connections": (
                snap.get("connections", {}).get("total", 0)
            ),
            "established": (
                snap.get("connections", {}).get("established", 0)
            ),
        })

    return {
        "status": status,
        "connected": connected,

        "last_seen": latest_sensor_snapshot.get("received_at"),
        "age_seconds": age_seconds,

        "device": latest_sensor_snapshot.get("device", "Unknown"),
        "interface": latest_sensor_snapshot.get("interface", "Unknown"),

        "upload_kbps": latest_sensor_snapshot.get("upload_kbps", 0.0),
        "download_kbps": latest_sensor_snapshot.get("download_kbps", 0.0),

        "bytes_sent_total": latest_sensor_snapshot.get("bytes_sent_total", 0),
        "bytes_received_total": latest_sensor_snapshot.get("bytes_received_total", 0),

        "packets_sent": latest_sensor_snapshot.get("packets_sent", 0),
        "packets_received": latest_sensor_snapshot.get("packets_received", 0),

        "errors_in": latest_sensor_snapshot.get("errors_in", 0),
        "errors_out": latest_sensor_snapshot.get("errors_out", 0),

        "connections": latest_sensor_snapshot.get(
            "connections",
            {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "established": 0,
            },
        ),

        "history": history_points,
        "history_count": len(sensor_history),

        "telemetry_type": "host_interface_counters",
        "model_compatible": False,

        "disclaimer": (
            "Host network interface telemetry (psutil). "
            "Distinct from the 74-feature bidirectional "
            "flow records used by the Random Forest model."
        ),
    }


# --------------------------------------------------
# AUTHENTICATED LATEST SENSOR SNAPSHOT
# --------------------------------------------------

@app.get("/api/sensor/latest")
def get_latest_sensor_snapshot(
    x_sentinel_token: str | None = Header(
        default=None,
        alias="X-Sentinel-Token",
    ),
):

    verify_sensor_token(x_sentinel_token)

    return {
        "latest": latest_sensor_snapshot,
        "history_count": len(sensor_history),
    }


# --------------------------------------------------
# LIVE FLOW INGESTION & ML INFERENCE
# --------------------------------------------------

@app.post("/api/sensor/flows")
def receive_sensor_flows(
    payload: SensorFlowBatch,
    x_sentinel_token: str | None = Header(
        default=None,
        alias="X-Sentinel-Token",
    ),
):

    verify_sensor_token(x_sentinel_token)

    if not payload.flows:

        return {
            "status": "ok",
            "processed_count": 0,
            "predictions": [],
            "live_stats": live_flow_stats,
        }

    model, feature_columns = get_cached_model()

    if model is None or feature_columns is None:

        raise HTTPException(
            status_code=503,
            detail=(
                "ML Model not available. "
                "Check artifacts/model.joblib."
            ),
        )

    valid_rows = []
    flow_items_valid = []

    for item in payload.flows:

        feats = item.features

        missing = [
            column
            for column in feature_columns
            if column not in feats
        ]

        if missing:

            logger.warning(
                "Flow %s:%s -> %s:%s rejected: "
                "missing %s features: %s",
                item.metadata.src_ip,
                item.metadata.src_port,
                item.metadata.dst_ip,
                item.metadata.dst_port,
                len(missing),
                missing[:5],
            )

            continue

        row_vals = {
            column: safe_float(
                feats[column],
                default=np.nan
            )
            for column in feature_columns
        }

        valid_rows.append(row_vals)
        flow_items_valid.append(item)

    if not valid_rows:

        return {
            "status": "rejected",
            "processed_count": 0,

            "detail": (
                "None of the submitted flows passed "
                "74-feature schema validation."
            ),

            "live_stats": live_flow_stats,
        }

    X = pd.DataFrame(
        valid_rows,
        columns=feature_columns
    )

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    probabilities = model.predict_proba(X)

    classes = list(model.classes_)

    if 1 not in classes:
        raise HTTPException(
            status_code=500,
            detail=f"Attack class 1 not found in model classes: {classes}",
        )

    attack_idx = classes.index(1)

    attack_probabilities = probabilities[:, attack_idx]

    predictions_binary = (
        attack_probabilities >= THRESHOLD
    ).astype(int)

    now_iso = datetime.now(
        timezone.utc
    ).isoformat()

    processed_results = []

    for idx, item in enumerate(flow_items_valid):

        is_attack = bool(
            predictions_binary[idx]
        )

        prob = safe_float(
            attack_probabilities[idx]
        )

        confidence = (
            prob
            if is_attack
            else 1.0 - prob
        )

        classification = (
            "ATTACK"
            if is_attack
            else "BENIGN"
        )

        severity = (
            "Critical"
            if is_attack and confidence >= 0.90
            else "High"
            if is_attack and confidence >= 0.75
            else "Medium"
            if is_attack
            else "Normal"
        )

        pred_record = {
            "id": "LIVE-" + uuid.uuid4().hex[:8].upper(),
            "timestamp": now_iso,
            "device": payload.device,

            "srcIp": item.metadata.src_ip,
            "dstIp": item.metadata.dst_ip,

            "srcPort": item.metadata.src_port,
            "dstPort": item.metadata.dst_port,

            "protocol": item.metadata.protocol,

            "flowDuration": item.features.get(
                "Flow Duration",
                0.0
            ),

            "totalPackets": item.metadata.total_packets,
            "totalBytes": item.metadata.total_bytes,

            "classification": classification,
            "confidence": round(confidence, 4),
            "attackProbability": round(prob, 4),
            "severity": severity,

            "source": "LIVE_SENSOR",
        }

        processed_results.append(pred_record)

        live_flow_history.appendleft(
            pred_record
        )

    total = len(processed_results)

    attacks = sum(
        1
        for prediction in processed_results
        if prediction["classification"] == "ATTACK"
    )

    normals = total - attacks

    live_flow_stats["total_flows"] += total
    live_flow_stats["normal_flows"] += normals
    live_flow_stats["malicious_flows"] += attacks

    if live_flow_stats["total_flows"] > 0:

        live_flow_stats["threat_rate"] = round(
            (
                live_flow_stats["malicious_flows"]
                / live_flow_stats["total_flows"]
            ) * 100,
            2,
        )

    live_flow_stats["last_flow_at"] = now_iso

    live_flow_stats["capture_method"] = (
        payload.capture_method
    )

    return {
        "status": "processed",
        "processed_count": total,
        "malicious_count": attacks,
        "normal_count": normals,
        "predictions": processed_results,
        "live_stats": live_flow_stats,
    }


# --------------------------------------------------
# LIVE SOC FEED
# --------------------------------------------------

@app.get("/api/sensor/live-feed")
def get_sensor_live_feed():

    status, connected, age = compute_sensor_age()

    feed_active = (
        connected
        and live_flow_stats["total_flows"] > 0
    )

    return {
        "status": (
            "active"
            if feed_active
            else "idle"
            if connected
            else "offline"
        ),

        "connected": connected,
        "sensor_age_seconds": age,

        "verified_pipeline": True,
        "schema_feature_count": 74,
        "decision_threshold": THRESHOLD,

        "stats": live_flow_stats,

        "recent_flows": list(
            live_flow_history
        )[:50],

        "source": "LIVE_SENSOR",
    }


# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    port = int(
        os.environ.get("PORT", 8000)
    )

    host = os.environ.get(
        "HOST",
        "0.0.0.0"
        if os.environ.get("RENDER")
        else "127.0.0.1"
    )

    logger.info(
        "Starting Sentinel Cyber FastAPI server "
        "on http://%s:%s ...",
        host,
        port,
    )

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=not bool(os.environ.get("RENDER")),
    )
