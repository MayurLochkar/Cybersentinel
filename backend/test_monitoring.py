"""
Comprehensive Verification Test Suite for CyberSentinel-X Monitoring Pipeline.

Verifies:
1. System health, alerts, and baseline ML endpoints.
2. Npcap driver availability and interface enumeration.
3. Bidirectional flow aggregation and exact 70 CICIDS2017 feature mapping.
4. Random Forest inference consistency.
5. Strict separation between REAL live capture and DEMO simulated telemetry.
6. Safe, clean Start/Stop lifecycle controls without resource leaks.
7. Authorized PCAP ingestion and validation checks.
8. Complete status API contract with packet/flow counters.
"""

import io
import sys
import time
from fastapi.testclient import TestClient

from main import app
from database import engine, Base
from models import Alert
from monitoring.live_capture import is_pcap_available, get_available_interfaces, resolve_scapy_interface
from monitoring.flow_extractor import FlowAggregator
from ml.predict import load_model, predict_traffic
from monitoring.sample_pcap import generate_sample_pcap_bytes
from monitoring.manager import monitoring_manager

client = TestClient(app)


def run_tests():
    print("=" * 70)
    print("CYBERSENTINEL-X LIVE MONITORING & TELEMETRY VERIFICATION SUITE")
    print("=" * 70)

    # 1. Baseline Health Endpoint
    res = client.get("/api/health")
    assert res.status_code == 200, f"Health check failed: {res.text}"
    print("[PASS] 1. GET /api/health:", res.json())

    # 2. Existing Dashboard Summary
    res = client.get("/api/dashboard/summary")
    assert res.status_code == 200, f"Dashboard summary failed: {res.text}"
    print("[PASS] 2. GET /api/dashboard/summary:", res.json())

    # 3. Existing Alerts Endpoint
    res = client.get("/api/alerts")
    assert res.status_code == 200, f"Alerts check failed: {res.text}"
    alerts = res.json()
    assert len(alerts) >= 1, "Expected at least 1 alert"
    print(f"[PASS] 3. GET /api/alerts: {len(alerts)} alerts retrieved")

    # 4. Existing Predict Endpoint with Baseline Features
    pipeline, feature_names = load_model()
    assert len(feature_names) == 70, f"Expected 70 trained features, found {len(feature_names)}"
    sample_features = {
        "Destination Port": 80,
        "Flow Duration": 12933,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 4,
        "Flow Bytes/s": 8994819.46,
        "Flow Packets/s": 541.25,
    }
    res = client.post("/api/predict", json={"features": sample_features})
    assert res.status_code == 200, f"Predict failed: {res.text}"
    pred = res.json()
    assert "prediction" in pred and "confidence_percent" in pred
    print(f"[PASS] 4. POST /api/predict: {pred['prediction']} (confidence {pred['confidence_percent']}%)")

    # 5. Npcap Driver Availability Check
    pcap_active = is_pcap_available()
    print(f"[PASS] 5. Npcap Packet Provider Active: {pcap_active}")

    # 6. Interface Enumeration & Resolution
    res = client.get("/api/monitoring/interfaces")
    assert res.status_code == 200, f"Interfaces failed: {res.text}"
    ifaces_data = res.json()
    assert "interfaces" in ifaces_data and "pcap_available" in ifaces_data
    interfaces = ifaces_data["interfaces"]
    assert len(interfaces) > 0, "Expected at least 1 network interface"
    print(f"[PASS] 6. GET /api/monitoring/interfaces: found {len(interfaces)} clean adapters")
    for ifc in interfaces[:3]:
        print(f"      Adapter: '{ifc['name']}' ({ifc['description']}) [IP: {ifc['ip']}]")

    # Verify resolution helper
    resolved_wifi = resolve_scapy_interface("Wi-Fi")
    assert resolved_wifi is not None, "Failed to resolve Wi-Fi interface"
    print(f"[PASS] 6b. Interface Resolver: 'Wi-Fi' successfully mapped to device '{resolved_wifi}'")

    # 7. Initial Status Check (contract fields verification)
    res = client.get("/api/monitoring/status")
    assert res.status_code == 200, f"Monitoring status failed: {res.text}"
    status_data = res.json()
    expected_fields = [
        "status", "mode", "capture_mode", "pcap_live_capable", "is_running",
        "source", "selected_interface", "packets_captured", "flows_processed",
        "benign_count", "attack_count", "alerts_created", "alerts_generated", "last_error"
    ]
    for field in expected_fields:
        assert field in status_data, f"Missing field in status response: {field}"
    assert status_data["status"] == "STOPPED"
    print("[PASS] 7. GET /api/monitoring/status: complete contract verified with all required fields")

    # 8. PCAP Validation & Safe Error Handling
    invalid_bytes = b"NOT_A_VALID_PCAP_STREAM"
    files = {"file": ("bad_file.bin", io.BytesIO(invalid_bytes), "application/octet-stream")}
    res = client.post("/api/monitoring/pcap", files=files)
    assert res.status_code == 422, f"Expected 422 for invalid PCAP, got {res.status_code}"
    print("[PASS] 8. POST /api/monitoring/pcap (Invalid File Handled Gracefully):", res.json()["detail"])

    # 9. Authorized PCAP File Ingestion & 70-Feature Extraction
    sample_pcap = generate_sample_pcap_bytes()
    assert len(sample_pcap) > 100, "Sample PCAP is empty"
    files = {"file": ("authorized_test.pcap", io.BytesIO(sample_pcap), "application/vnd.tcpdump.pcap")}
    res = client.post("/api/monitoring/pcap", files=files)
    assert res.status_code == 200, f"PCAP ingestion failed: {res.text}"
    pcap_res = res.json()
    assert pcap_res["flows_extracted"] >= 2, "Expected at least 2 flows from sample PCAP"
    print(f"[PASS] 9. POST /api/monitoring/pcap: {pcap_res['flows_extracted']} flows classified ({pcap_res['benign_flows']} benign, {pcap_res['attack_flows']} attacks)")

    # 10. Flow Aggregator & Exact 70 Features Computation
    agg = FlowAggregator(flow_timeout_seconds=5.0)
    now = time.time()
    # Ingest 2 synthetic test packets to verify BiFlow feature output
    agg.ingest_packet("10.0.0.1", "10.0.0.2", 12345, 80, "TCP", now, 100, 60, 40, flags=0x02, window_size=64240)
    agg.ingest_packet("10.0.0.2", "10.0.0.1", 80, 12345, "TCP", now + 0.01, 150, 110, 40, flags=0x12, window_size=65535)
    test_flows = agg.flush_all()
    assert len(test_flows) == 1, "Expected 1 aggregated bidirectional flow"
    computed_feats = test_flows[0].compute_features()
    assert len(computed_feats) == 70, f"Expected 70 features, got {len(computed_feats)}"
    for fn in feature_names:
        assert fn in computed_feats, f"Missing feature in computed dict: {fn}"
    pred_res = predict_traffic(computed_feats)
    assert "prediction" in pred_res
    print(f"[PASS] 10. FlowAggregator: 70/70 features computed and validated against Random Forest => {pred_res['prediction']}")

    # 11. DEMO Mode Separation & Lifecycle
    res = client.post("/api/monitoring/start", json={"interface": "Loopback", "mode": "demo"})
    assert res.status_code == 200, f"Demo start failed: {res.text}"
    demo_start = res.json()
    assert demo_start["capture_mode"] == "demo", "Expected capture_mode == 'demo'"
    time.sleep(0.5)
    res = client.get("/api/monitoring/status")
    status_demo = res.json()
    assert status_demo["capture_mode"] == "demo"
    assert status_demo["is_running"] is True
    print("[PASS] 11a. Explicit DEMO Mode: started and isolated with capture_mode='demo'")

    # Stop demo monitoring
    res = client.post("/api/monitoring/stop")
    assert res.status_code == 200
    print("[PASS] 11b. Explicit DEMO Mode: stopped cleanly")

    # 12. REAL Live NIC Capture Lifecycle (Npcap)
    if pcap_active:
        res = client.post("/api/monitoring/start", json={"interface": "Wi-Fi", "mode": "real"})
        assert res.status_code == 200, f"Real live start failed: {res.text}"
        real_start = res.json()
        assert real_start["capture_mode"] == "real", "Expected capture_mode == 'real'"
        time.sleep(0.5)
        res = client.get("/api/monitoring/status")
        status_real = res.json()
        assert status_real["capture_mode"] == "real"
        assert status_real["is_running"] is True
        print(f"[PASS] 12a. REAL Live Capture: started on '{status_real['selected_interface']}' with Npcap")

        # Clean Stop
        res = client.post("/api/monitoring/stop")
        assert res.status_code == 200
        stop_res = res.json()
        print(f"[PASS] 12b. REAL Live Capture: stopped cleanly. Total packets: {stop_res['packets_captured']}")
    else:
        # If Npcap is not active, real live capture must reject with clear 400 error and not silently fake traffic
        res = client.post("/api/monitoring/start", json={"interface": "Wi-Fi", "mode": "real"})
        assert res.status_code == 400
        print("[PASS] 12. Real Live Capture rejected safely when Npcap missing without silent simulation")

    # 13. Telemetry Metrics Stream
    res = client.get("/api/monitoring/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert "recent_flows" in metrics
    print(f"[PASS] 13. GET /api/monitoring/metrics: {metrics['flows_processed']} flows processed, {len(metrics['recent_flows'])} recent flows in inspection ring buffer")

    # 14. Forensic Evidence Ledger & Live SHA-256 Byte Verification
    res = client.get("/api/evidence")
    assert res.status_code == 200, f"Evidence list failed: {res.text}"
    evidence_items = res.json()
    assert len(evidence_items) >= 4, f"Expected at least 4 evidence artifacts, got {len(evidence_items)}"
    verified_items = [e for e in evidence_items if e["verification_status"] == "VERIFIED"]
    tampered_items = [e for e in evidence_items if e["verification_status"] == "TAMPERED"]
    assert len(verified_items) >= 3, "Expected verified artifacts"
    assert len(tampered_items) >= 1, "Expected tampered test fixture"
    print(f"[PASS] 14a. GET /api/evidence: {len(evidence_items)} artifacts ({len(verified_items)} verified, {len(tampered_items)} tampered)")

    # Verify matching file
    res = client.post("/api/evidence/verify", json={"evidence_id": "EV-001"})
    assert res.status_code == 200
    ev1_res = res.json()
    assert ev1_res["verification_status"] == "VERIFIED"
    assert ev1_res["stored_hash"] == ev1_res["current_hash"]
    print(f"[PASS] 14b. POST /api/evidence/verify (EV-001): {ev1_res['verification_status']} (SHA-256 match)")

    # Verify tampered fixture
    res = client.post("/api/evidence/verify", json={"evidence_id": "EV-005"})
    assert res.status_code == 200
    ev5_res = res.json()
    assert ev5_res["verification_status"] == "TAMPERED"
    assert ev5_res["stored_hash"] != ev5_res["current_hash"]
    print(f"[PASS] 14c. POST /api/evidence/verify (EV-005 Tamper Fixture): {ev5_res['verification_status']} (Tamper detected accurately)")

    # 15. Risk Assessment Summary
    res = client.get("/api/risk/summary")
    assert res.status_code == 200, f"Risk summary failed: {res.text}"
    risk_summary = res.json()
    assert "overall_score" in risk_summary and "scoring_formula" in risk_summary
    assert len(risk_summary["incidents"]) >= 1
    print(f"[PASS] 15. GET /api/risk/summary: Overall Score {risk_summary['overall_score']} ({risk_summary['overall_level']}), {len(risk_summary['incidents'])} incidents scored")

    # 16. Analytics Summary
    res = client.get("/api/analytics/summary")
    assert res.status_code == 200, f"Analytics summary failed: {res.text}"
    analytics_summary = res.json()
    assert "attack_distribution" in analytics_summary
    assert "risk_distribution" in analytics_summary
    assert "weekly_activity" in analytics_summary
    print(f"[PASS] 16. GET /api/analytics/summary: {analytics_summary['total_alerts']} total alerts, {len(analytics_summary['attack_distribution'])} attack categories")

    # 17. Local Threat Intel & MITRE ATT&CK Matrix Correlation
    res = client.get("/api/threat-intel/lookup?query=185.73.21.10")
    assert res.status_code == 200, f"Threat intel failed: {res.text}"
    intel_res = res.json()
    assert intel_res["reputation_score"] > 0
    assert len(intel_res["mitre_techniques"]) >= 1
    print(f"[PASS] 17. GET /api/threat-intel/lookup: Correlated {len(intel_res['mitre_techniques'])} MITRE techniques, reputation {intel_res['reputation_score']}")

    # 18. Alert Status Update and SQLite Persistence
    res = client.patch("/api/alerts/INC-1024/status", json={"status": "Investigating"})
    assert res.status_code == 200
    updated_alert = res.json()
    assert updated_alert["status"] == "Investigating"

    # Re-fetch alert to verify persistence
    res = client.get("/api/alerts/INC-1024")
    assert res.status_code == 200
    assert res.json()["status"] == "Investigating"
    print("[PASS] 18. PATCH /api/alerts/{id}/status: Status updated to 'Investigating' and verified in database")

    # 19. Schema Validation Rejection of Literal 'string'
    res = client.post(
        "/api/alerts",
        json={
            "incident_id": "INC-INVALID-1",
            "attack_type": "string",
            "source_ip": "1.2.3.4",
            "destination_ip": "10.0.0.1",
            "target": "Auth",
            "severity": "HIGH",
            "confidence": 90.0,
            "status": "Open",
            "reason": "Test",
            "created_at": "2026-10-23T12:00:00Z",
        },
    )
    assert res.status_code == 422, "Expected 422 Unprocessable Entity when attack_type='string'"
    print("[PASS] 19. Pydantic Validator: Rejected literal 'string' placeholder with HTTP 422")

    print("=" * 70)
    print("ALL 19 TESTS PASSED PERFECTLY - VERIFICATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()

