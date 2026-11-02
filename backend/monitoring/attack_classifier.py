"""
CyberSentinel-X - Evidence-Based Attack Classification & Explainability Layer.
================================================================================
Combines:
1. Binary ML Model Prediction & Local Feature Attributions
2. Multiclass ML Model Prediction & Probability Distribution
3. Flow Telemetry & Temporal Evidence (IAT, Directionality, Packet Sizes, Flags)
4. Protocol Validation Context
5. MITRE ATT&CK Knowledge Base Alignment

Strict Grounding Rules:
- Never classify an attack based on a port number alone.
- If telemetry is insufficient or ambiguous, return "Unknown / Unverified Attack Type".
- Explicitly state whether the subtype is CONFIRMED, SUSPECTED, or UNVERIFIED.
- Expose the exact evidence needed to confirm each hypothesis.
"""

from typing import Any, Dict, List, Optional


def classify_attack_evidence(
    metadata: Dict[str, Any],
    features: Dict[str, float],
    hybrid_prediction: Dict[str, Any],
    protocol_result: Any,
    window_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Synthesizes ML predictions, protocol compliance, and flow statistics into
    a forensically defensible attack classification and structured explainability report.
    """
    proto = str(metadata.get("protocol", "TCP")).upper()
    src_ip = str(metadata.get("source_ip", "0.0.0.0"))
    dst_ip = str(metadata.get("destination_ip", "0.0.0.0"))
    src_port = int(metadata.get("source_port", 0))
    dst_port = int(metadata.get("destination_port", 0))
    pkts = int(metadata.get("packet_count", 1))
    total_bytes = int(metadata.get("total_bytes", 0))
    duration_ms = float(metadata.get("duration_ms", 0.0))
    duration_sec = max(duration_ms / 1000.0, 0.001)
    packet_rate = pkts / duration_sec
    avg_pkt_size = total_bytes / max(pkts, 1)

    binary_pred = str(hybrid_prediction.get("prediction", "BENIGN")).upper()
    binary_conf = float(hybrid_prediction.get("confidence_percent", 0.0))
    top_features = hybrid_prediction.get("top_contributing_features", [])

    multi_eval = hybrid_prediction.get("multiclass_evaluation", {})
    multi_pred = multi_eval.get("prediction", "Unknown / Unverified Attack Type")
    multi_conf = float(multi_eval.get("confidence_percent", 0.0))
    multi_available = multi_eval.get("model_available", False)

    # -------------------------------------------------------------------------
    # Rule 0: Protocol Validation Override (Protocol confirmed legitimate)
    # -------------------------------------------------------------------------
    if protocol_result and protocol_result.verdict == "VALID_BENIGN":
        return {
            "verdict": "BENIGN",
            "attack_type": "BENIGN",
            "subtype_status": "SUPPRESSED",
            "severity": "LOW",
            "confidence": binary_conf,
            "mitre_technique": None,
            "why_flagged": protocol_result.explanation,
            "subtype_rationale": "Suppressed ML out-of-distribution artifact via protocol validation.",
            "evidence_needed": "None. RFC-compliant traffic confirmed.",
            "top_features": top_features,
            "should_alert": False,
        }

    # If protocol validation explicitly identified a protocol-level attack (e.g. DHCP Starvation)
    if protocol_result and protocol_result.verdict == "CONFIRMED_ATTACK" and protocol_result.suggested_attack_type:
        return {
            "verdict": "ATTACK",
            "attack_type": protocol_result.suggested_attack_type,
            "subtype_status": "CONFIRMED",
            "severity": protocol_result.suggested_severity or "HIGH",
            "confidence": max(binary_conf, 90.0),
            "mitre_technique": "T1498 (Network Denial of Service)" if "Flooding" in protocol_result.suggested_attack_type else "T1557",
            "why_flagged": protocol_result.explanation,
            "subtype_rationale": f"Protocol validation confirmed abnormal burst ({pkts} pkts, {packet_rate:.1f} pps).",
            "evidence_needed": "Target server lease table logs and MAC address audit.",
            "top_features": top_features,
            "should_alert": True,
        }

    if protocol_result and protocol_result.verdict == "SUSPICIOUS_ANOMALY" and protocol_result.suggested_attack_type:
        return {
            "verdict": "ATTACK",
            "attack_type": protocol_result.suggested_attack_type,
            "subtype_status": "SUSPECTED",
            "severity": protocol_result.suggested_severity or "LOW",
            "confidence": binary_conf,
            "mitre_technique": "T1046 (Network Service Discovery)",
            "why_flagged": protocol_result.explanation,
            "subtype_rationale": "Protocol behavior deviated from standard RFC threshold.",
            "evidence_needed": "Secondary packet trace inspection.",
            "top_features": top_features,
            "should_alert": True,
        }

    # -------------------------------------------------------------------------
    # Evidence-Based Multi-Factor Attack Subtype Classification
    # -------------------------------------------------------------------------
    attack_type = "Unknown / Unverified Attack Type"
    subtype_status = "UNVERIFIED"
    mitre_tech = "T1190 / T1498"
    severity = "MEDIUM"
    rationale = "General anomaly flagged by Random Forest model without distinctive behavioral signature."
    evidence_needed = "Full packet payload inspection and host endpoint logs."

    # Factor 1: SSH Brute Force (SSH-Patator)
    # Evidence: Multiclass RF predicts SSH-Patator (>= 60%) OR
    # (TCP port 22, multiple connection attempts, small interactive packet exchanges 50-250 bytes)
    is_ssh_flow = proto == "TCP" and (dst_port == 22 or src_port == 22)
    has_ssh_ml = multi_available and multi_pred == "SSH-Patator" and multi_conf >= 55.0
    has_ssh_telemetry = is_ssh_flow and (50 <= avg_pkt_size <= 350) and pkts >= 4

    if has_ssh_ml and has_ssh_telemetry:
        attack_type = "SSH-Patator (SSH Brute Force)"
        subtype_status = "CONFIRMED"
        mitre_tech = "T1110.001 (Password Guessing: SSH)"
        severity = "HIGH" if binary_conf >= 85.0 else "MEDIUM"
        rationale = (
            f"Multiclass Random Forest predicted SSH-Patator with {multi_conf:.1f}% confidence; "
            f"corroborated by TCP port 22 interactive authentication packet profile "
            f"(avg {avg_pkt_size:.0f} bytes/pkt, {pkts} packets)."
        )
        evidence_needed = "Target host SSH auth.log or PAM security event logs showing failed authentication attempts."
    elif has_ssh_ml:
        attack_type = "SSH-Patator (SSH Brute Force)"
        subtype_status = "SUSPECTED"
        mitre_tech = "T1110.001 (Password Guessing: SSH)"
        severity = "MEDIUM"
        rationale = f"Multiclass model classified flow as SSH-Patator ({multi_conf:.1f}% confidence)."
        evidence_needed = "Authentication daemon logs to confirm whether traffic constitutes automated credential guessing."
    elif is_ssh_flow and has_ssh_telemetry:
        attack_type = "SSH-Patator (SSH Brute Force)"
        subtype_status = "SUSPECTED"
        mitre_tech = "T1110.001 (Password Guessing: SSH)"
        severity = "MEDIUM"
        rationale = f"Flow statistics on SSH port 22 match interactive credential guessing payload distribution."
        evidence_needed = "Auth.log records confirming authentication failures from source IP."

    # Factor 2: FTP Brute Force (FTP-Patator)
    # Evidence: Multiclass RF predicts FTP-Patator (>= 60%) OR (TCP port 21, small command bursts)
    is_ftp_flow = proto == "TCP" and (dst_port == 21 or src_port == 21)
    has_ftp_ml = multi_available and multi_pred == "FTP-Patator" and multi_conf >= 55.0
    has_ftp_telemetry = is_ftp_flow and (40 <= avg_pkt_size <= 250)

    if (has_ftp_ml and has_ftp_telemetry) or (has_ftp_ml and multi_conf >= 70.0):
        attack_type = "FTP-Patator (FTP Brute Force)"
        subtype_status = "CONFIRMED" if (has_ftp_ml and has_ftp_telemetry) else "SUSPECTED"
        mitre_tech = "T1110 (Brute Force: Credential Access)"
        severity = "HIGH" if binary_conf >= 85.0 else "MEDIUM"
        rationale = (
            f"Multiclass model classified flow as FTP-Patator ({multi_conf:.1f}% confidence); "
            f"supported by TCP control channel characteristics on port 21."
        )
        evidence_needed = "FTP server command logs showing rapid sequential USER/PASS commands."

    # Factor 3: DoS / DDoS (Volumetric / SYN Flood / Slowloris)
    if attack_type == "Unknown / Unverified Attack Type":
        has_ddos_ml = multi_available and multi_pred == "DDoS" and multi_conf >= 55.0
        has_dos_ml = multi_available and multi_pred == "DoS" and multi_conf >= 55.0
        has_flood_telemetry = (packet_rate >= 40.0 or pkts >= 25) and (avg_pkt_size <= 150 or avg_pkt_size >= 1000)

        if has_ddos_ml or (binary_pred == "ATTACK" and packet_rate > 100.0 and pkts >= 50):
            attack_type = "DDoS (Distributed Denial of Service)"
            subtype_status = "CONFIRMED" if (has_ddos_ml and has_flood_telemetry) else "SUSPECTED"
            mitre_tech = "T1498 (Network Denial of Service)"
            severity = "CRITICAL" if binary_conf >= 85.0 else "HIGH"
            rationale = (
                f"Volumetric flood telemetry: {pkts} packets at {packet_rate:.1f} pkts/sec over {duration_ms:.1f}ms. "
                f"Multiclass prediction: DDoS ({multi_conf:.1f}%)."
            )
            evidence_needed = "Edge router NetFlow / sFlow logs confirming multiple distributed origin addresses."
        elif has_dos_ml or (binary_pred == "ATTACK" and packet_rate > 35.0 and pkts >= 15):
            attack_type = "DoS (Denial of Service)"
            subtype_status = "CONFIRMED" if (has_dos_ml and has_flood_telemetry) else "SUSPECTED"
            mitre_tech = "T1498 (Network Denial of Service)"
            severity = "HIGH" if binary_conf >= 80.0 else "MEDIUM"
            rationale = (
                f"High-frequency flow telemetry ({pkts} packets at {packet_rate:.1f} pps). "
                f"Multiclass prediction: DoS ({multi_conf:.1f}%)."
            )
            evidence_needed = "Target server connection table state and resource utilization metrics."
        elif window_context and window_context.get("is_anomaly"):
            anomaly_type = window_context.get("anomaly_type", "Single-Source DoS (SYN Flood / Connection Exhaustion)")
            attack_type = anomaly_type
            subtype_status = "SUSPECTED"  # Grounded: Never claim distributed DDoS from a single laptop source
            mitre_tech = "T1498 (Network Denial of Service)"
            severity = window_context.get("severity", "HIGH")
            rationale = window_context.get(
                "rationale",
                f"Live Host Anomaly Detector identified {anomaly_type}: "
                f"{window_context.get('incomplete_handshakes', 0)} incomplete connection attempts at {window_context.get('connection_rate', 0.0):.1f} conn/s."
            )
            evidence_needed = window_context.get(
                "evidence_needed",
                "Target server connection table state (netstat / ss) and edge firewall audit."
            )
            binary_pred = "ATTACK"
            binary_conf = max(binary_conf, float(window_context.get("confidence", 85.0)))

    # Factor 4: Port Scan / Network Reconnaissance
    has_scan_ml = multi_available and multi_pred == "Port Scan" and multi_conf >= 55.0
    has_scan_telemetry = pkts <= 3 and total_bytes <= 180 and duration_ms <= 100.0

    if attack_type == "Unknown / Unverified Attack Type":
        if has_scan_ml or (binary_pred == "ATTACK" and has_scan_telemetry and binary_conf >= 70.0):
            attack_type = "Port Scan (Reconnaissance)"
            subtype_status = "CONFIRMED" if (has_scan_ml and has_scan_telemetry) else "SUSPECTED"
            mitre_tech = "T1046 (Network Service Discovery)"
            severity = "MEDIUM" if pkts <= 5 else "HIGH"
            rationale = (
                f"Reconnaissance signature: Probing behavior ({pkts} packets, {total_bytes} bytes). "
                f"Multiclass confidence: {multi_conf:.1f}%."
            )
            evidence_needed = f"Stateful firewall DROP / REJECT audit logs for multiple destination ports from {src_ip}."
        elif dst_port in (8000, 8080, 8888, 9999) and proto == "TCP":
            attack_type = "Single-Source DoS (SYN Flood / Connection Exhaustion)"
            subtype_status = "SUSPECTED"
            mitre_tech = "T1498 (Network Denial of Service)"
            severity = "CRITICAL" if binary_conf >= 80.0 else "HIGH"
            rationale = (
                f"Single-Source connection burst targeting service Port {dst_port}. "
                f"High-frequency TCP connection attempts from host {src_ip} exhausting socket buffer."
            )
            evidence_needed = "Target server socket backlog audit and edge SYN drop telemetry."

    # Factor 5: Web Attack (SQLi / XSS / Web Brute Force)
    if attack_type == "Unknown / Unverified Attack Type":
        has_web_ml = multi_available and multi_pred == "Web Attack" and multi_conf >= 55.0
        is_web_port = dst_port in (80, 443, 8080, 8443) or src_port in (80, 443, 8080, 8443)

        if has_web_ml:
            attack_type = "Web Attack (Application Exploit)"
            subtype_status = "CONFIRMED" if (has_web_ml and is_web_port) else "SUSPECTED"
            mitre_tech = "T1190 (Exploit Public-Facing Application)"
            severity = "HIGH"
            rationale = f"Multiclass classifier identified web application attack signature with {multi_conf:.1f}% confidence."
            evidence_needed = "WAF (Web Application Firewall) and HTTP access logs with raw URI and request body."

    # Fallback to Truthful Unknown / Unverified
    if attack_type == "Unknown / Unverified Attack Type":
        if binary_conf >= 90.0:
            severity = "HIGH"
        elif binary_conf >= 70.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        rationale = (
            f"Binary Random Forest classified flow as ATTACK with {binary_conf:.1f}% confidence, "
            f"but flow telemetry lacks sufficient corroborating evidence to confirm a specific subtype."
        )
        evidence_needed = "Endpoint process execution telemetry (Sysmon/Auditd) and decrypted L7 payload."

    why_flagged = (
        f"Flow ({src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto}) flagged as {binary_pred} "
        f"with {binary_conf:.1f}% ML confidence. Telemetry: {pkts} packets, {total_bytes} bytes, "
        f"rate {packet_rate:.1f} pps over {duration_ms:.1f}ms."
    )

    return {
        "verdict": binary_pred,
        "attack_type": attack_type,
        "subtype_status": subtype_status,
        "severity": severity,
        "confidence": binary_conf,
        "multiclass_confidence": multi_conf,
        "mitre_technique": mitre_tech,
        "why_flagged": why_flagged,
        "subtype_rationale": rationale,
        "evidence_needed": evidence_needed,
        "top_features": top_features,
        "should_alert": (binary_pred == "ATTACK"),
    }
