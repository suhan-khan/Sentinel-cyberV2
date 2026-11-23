"""
Sentinel Cyber — Backend API Automated Verification Suite
Tests all endpoints: Health, CSV Ingestion, ML Inference, Sensor Authentication,
Live 74-Feature Flow Ingestion, Live Feed, and Rejection of Invalid Tokens.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(BACKEND_DIR / "sensor"))

from fastapi.testclient import TestClient
from main import app, get_cached_model, SENSOR_TOKEN, THRESHOLD
from sensor.flow_extractor import Flow, parse_ipv4_packet
from tests.test_flow_extraction import make_raw_ipv4_tcp_packet, make_raw_ipv4_udp_packet

client = TestClient(app)


def test_1_health_and_model_loading():
    print("[TEST 1] Testing /api/health and ML model loading...")
    response = client.get("/api/health")
    assert response.status_code == 200, f"Health returned {response.status_code}"
    data = response.json()

    assert data["status"] == "online"
    assert data["model_ready"] is True
    assert data["feature_count"] == 74
    assert data["threshold"] == 0.05
    assert data["model"]["label"] == "Random Forest"
    print("    [PASS] Health and model readiness verified.")


def test_2_sample_dataset_and_csv_prediction():
    print("[TEST 2] Testing sample dataset and CSV prediction...")
    res_sample = client.get("/api/sample-dataset")
    assert res_sample.status_code == 200
    sample_data = res_sample.json()
    dataset_id = sample_data["datasetId"]
    assert dataset_id == "DS-SAMPLE-CICIDS2017"
    assert sample_data["rows"] == 3
    assert len(sample_data["columns"]) == 74

    # Predict using sample dataset
    res_pred = client.post("/api/predict", json={"dataset_id": dataset_id})
    assert res_pred.status_code == 200, f"Predict failed: {res_pred.text}"
    pred_data = res_pred.json()

    assert "predictions" in pred_data
    assert len(pred_data["predictions"]) == 3
    for p in pred_data["predictions"]:
        assert "classification" in p
        assert p["classification"] in ["BENIGN", "ATTACK"]
        assert "confidence" in p
        assert 0.0 <= p["confidence"] <= 1.0

    print("    [PASS] CSV prediction pipeline verified.")


def test_3_sensor_authentication_and_snapshot():
    print("[TEST 3] Testing sensor authentication & snapshot ingestion...")
    valid_token = SENSOR_TOKEN or "sentinel-local-dev-token"
    invalid_token = "wrong-unauthorized-token-xyz"

    snapshot_payload = {
        "timestamp": "2026-11-23T12:00:00Z",
        "device": "TEST-LAPTOP",
        "interface": "Wi-Fi",
        "upload_kbps": 150.5,
        "download_kbps": 820.0,
        "bytes_sent_total": 1024000,
        "bytes_received_total": 5120000,
        "packets_sent": 500,
        "packets_received": 1200,
        "errors_in": 0,
        "errors_out": 0,
        "connections": {
            "total": 25,
            "tcp": 20,
            "udp": 5,
            "established": 12
        }
    }

    # 1. Invalid token should be rejected with 401
    res_bad = client.post(
        "/api/sensor/snapshot",
        json=snapshot_payload,
        headers={"X-Sentinel-Token": invalid_token}
    )
    assert res_bad.status_code == 401, f"Expected 401 Unauthorized, got {res_bad.status_code}"

    # 2. Valid token should succeed
    res_good = client.post(
        "/api/sensor/snapshot",
        json=snapshot_payload,
        headers={"X-Sentinel-Token": valid_token}
    )
    assert res_good.status_code == 200, f"Expected 200 OK, got {res_good.status_code}"
    assert res_good.json()["status"] == "received"

    # 3. Public telemetry endpoint should reflect the snapshot without requiring auth
    res_telem = client.get("/api/sensor/telemetry")
    assert res_telem.status_code == 200
    t_data = res_telem.json()
    assert t_data["connected"] is True
    assert t_data["device"] == "TEST-LAPTOP"
    assert t_data["upload_kbps"] == 150.5

    print("    [PASS] Sensor authentication and telemetry endpoints verified.")


def test_4_live_flow_ingestion_and_live_feed():
    print("[TEST 4] Testing live 74-feature flow ingestion & live-feed...")
    valid_token = SENSOR_TOKEN or "sentinel-local-dev-token"

    # Build 2 realistic flows
    now = time.time()
    raw_tcp = make_raw_ipv4_tcp_packet("192.168.1.15", "104.26.12.31", 54321, 443, flags=0x02, window_size=64240)
    raw_udp = make_raw_ipv4_udp_packet("192.168.1.15", "8.8.8.8", 51234, 53, payload=b"dns_test_packet")

    flow1 = Flow(parse_ipv4_packet(raw_tcp, now))
    flow2 = Flow(parse_ipv4_packet(raw_udp, now + 0.010))

    flows_payload = {
        "device": "TEST-LAPTOP",
        "timestamp": "2026-11-23T12:00:00Z",
        "capture_method": "flow_extractor_unit_test",
        "flows": [
            {"metadata": flow1.metadata(), "features": flow1.to_74_features()},
            {"metadata": flow2.metadata(), "features": flow2.to_74_features()}
        ]
    }

    # 1. Invalid token should be rejected
    res_unauth = client.post(
        "/api/sensor/flows",
        json=flows_payload,
        headers={"X-Sentinel-Token": "bad-token"}
    )
    assert res_unauth.status_code == 401

    # 2. Valid token should process flows and return predictions
    res_flows = client.post(
        "/api/sensor/flows",
        json=flows_payload,
        headers={"X-Sentinel-Token": valid_token}
    )
    assert res_flows.status_code == 200, f"Live flows failed: {res_flows.text}"
    flows_data = res_flows.json()
    assert flows_data["status"] == "processed"
    assert flows_data["processed_count"] == 2
    assert len(flows_data["predictions"]) == 2

    # Check prediction fields
    for p in flows_data["predictions"]:
        assert "id" in p
        assert p["id"].startswith("LIVE-")
        assert "classification" in p
        assert p["classification"] in ["BENIGN", "ATTACK"]
        assert "confidence" in p
        assert "attackProbability" in p
        assert "srcIp" in p
        assert "dstIp" in p
        assert "source" == "LIVE_SENSOR"

    # 3. Test rejection of incomplete flows (missing 74 features)
    bad_flows_payload = {
        "device": "TEST-LAPTOP",
        "timestamp": "2026-11-23T12:00:00Z",
        "capture_method": "broken_stream",
        "flows": [
            {
                "metadata": flow1.metadata(),
                "features": {"Destination Port": 80, "Flow Duration": 100}  # Only 2 features instead of 74!
            }
        ]
    }
    res_incomplete = client.post(
        "/api/sensor/flows",
        json=bad_flows_payload,
        headers={"X-Sentinel-Token": valid_token}
    )
    assert res_incomplete.status_code == 200
    assert res_incomplete.json()["status"] == "rejected"
    assert res_incomplete.json()["processed_count"] == 0

    # 4. Check /api/sensor/live-feed
    res_feed = client.get("/api/sensor/live-feed")
    assert res_feed.status_code == 200
    feed_data = res_feed.json()
    assert feed_data["source"] == "LIVE_SENSOR"
    assert feed_data["schema_feature_count"] == 74
    assert feed_data["stats"]["total_flows"] >= 2
    assert len(feed_data["recent_flows"]) >= 2
    assert feed_data["recent_flows"][0]["id"].startswith("LIVE-")

    print("    [PASS] Live flow ingestion, schema validation, and live-feed endpoints verified.")


def test_5_history_and_analytics_endpoints():
    print("[TEST 5] Testing /api/history and /api/analytics...")
    res_hist = client.get("/api/history")
    assert res_hist.status_code == 200
    assert isinstance(res_hist.json(), list)

    res_anal = client.get("/api/analytics")
    assert res_anal.status_code == 200
    assert "totalConnections" in res_anal.json()
    print("    [PASS] History and analytics endpoints verified.")


if __name__ == "__main__":
    print("=" * 65)
    print("  RUNNING FASTAPI BACKEND API VERIFICATION SUITE")
    print("=" * 65)
    test_1_health_and_model_loading()
    test_2_sample_dataset_and_csv_prediction()
    test_3_sensor_authentication_and_snapshot()
    test_4_live_flow_ingestion_and_live_feed()
    test_5_history_and_analytics_endpoints()
    print("\n[SUCCESS] ALL FASTAPI BACKEND TESTS PASSED CLEANLY!")
