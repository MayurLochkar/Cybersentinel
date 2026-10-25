import os
import json
import hashlib
from pathlib import Path
from scapy.all import wrpcap, IP, TCP, Raw

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence_storage"
EVIDENCE_DIR.mkdir(exist_ok=True)

# 1. authentication_logs_1024.json
auth_events = [
    {"timestamp": "2026-10-21T05:35:10Z", "src_ip": "185.73.21.10", "event": "AUTH_FAILED", "user": "admin", "service": "ssh"},
    {"timestamp": "2026-10-21T05:35:14Z", "src_ip": "185.73.21.10", "event": "AUTH_FAILED", "user": "root", "service": "ssh"},
    {"timestamp": "2026-10-21T05:35:18Z", "src_ip": "185.73.21.10", "event": "AUTH_FAILED", "user": "support", "service": "ssh"},
    {"timestamp": "2026-10-21T05:35:22Z", "src_ip": "185.73.21.10", "event": "AUTH_FAILED", "user": "service_account", "service": "ssh"},
    {"timestamp": "2026-10-21T05:35:26Z", "src_ip": "185.73.21.10", "event": "AUTH_FAILED", "user": "oracle", "service": "ssh"},
]
auth_file = EVIDENCE_DIR / "authentication_logs_1024.json"
auth_file.write_text(json.dumps(auth_events, indent=2), encoding="utf-8")

# 2. network_capture.pcap
pcap_file = EVIDENCE_DIR / "network_capture.pcap"
pkts = [
    IP(src="103.44.18.91", dst="10.0.0.8") / TCP(sport=54321 + i, dport=80, flags="S", seq=1000 * i) / Raw(load=b"SYN_FLOOD_TEST")
    for i in range(20)
]
wrpcap(str(pcap_file), pkts)

# 3. honeypot_telemetry.log
honeypot_file = EVIDENCE_DIR / "honeypot_telemetry.log"
honeypot_text = """[2026-10-21 05:34:01 UTC] [HONEYPOT-SENSOR-03] INBOUND TCP SYN from 45.91.22.17:41021 to 10.0.0.15:21 (FTP) - CONNECTION REFUSED
[2026-10-21 05:34:02 UTC] [HONEYPOT-SENSOR-03] INBOUND TCP SYN from 45.91.22.17:41022 to 10.0.0.15:22 (SSH) - BANNER SENT: OpenSSH_8.2p1
[2026-10-21 05:34:03 UTC] [HONEYPOT-SENSOR-03] INBOUND TCP SYN from 45.91.22.17:41023 to 10.0.0.15:23 (TELNET) - CONNECTION REFUSED
[2026-10-21 05:34:04 UTC] [HONEYPOT-SENSOR-03] INBOUND TCP SYN from 45.91.22.17:41024 to 10.0.0.15:80 (HTTP) - HTTP HEAD PROBE DETECTED
"""
honeypot_file.write_text(honeypot_text, encoding="utf-8")

# 4. kernel_audit_telemetry.bin
kernel_file = EVIDENCE_DIR / "kernel_audit_telemetry.bin"
kernel_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\xde\xad\xbe\xef" * 128
kernel_file.write_bytes(kernel_bytes)

# 5. tampered_artifact.log
tampered_file = EVIDENCE_DIR / "tampered_artifact.log"
tampered_file.write_text("ORIGINAL CONTENT RECORDED BEFORE TAMPERING", encoding="utf-8")

def get_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

evidence_catalog = [
    {
        "id": "EV-001",
        "file_name": "authentication_logs_1024.json",
        "incident_id": "INC-1024",
        "stored_hash": get_hash(auth_file),
        "file_size": f"{auth_file.stat().st_size} B",
        "blockchain_status": "Recorded",
        "timestamp": "2026-10-21 05:36:00 UTC",
        "recorded_block": "#0x8F91A204C",
    },
    {
        "id": "EV-002",
        "file_name": "network_capture.pcap",
        "incident_id": "INC-1022",
        "stored_hash": get_hash(pcap_file),
        "file_size": f"{pcap_file.stat().st_size} B",
        "blockchain_status": "Recorded",
        "timestamp": "2026-10-21 05:36:08 UTC",
        "recorded_block": "#0x8F91A198B",
    },
    {
        "id": "EV-003",
        "file_name": "honeypot_telemetry.log",
        "incident_id": "INC-1023",
        "stored_hash": get_hash(honeypot_file),
        "file_size": f"{honeypot_file.stat().st_size} B",
        "blockchain_status": "Recorded",
        "timestamp": "2026-10-21 05:36:12 UTC",
        "recorded_block": "#0x8F91A172D",
    },
    {
        "id": "EV-004",
        "file_name": "kernel_audit_telemetry.bin",
        "incident_id": "INC-LIVE-AUDIT",
        "stored_hash": get_hash(kernel_file),
        "file_size": f"{kernel_file.stat().st_size} B",
        "blockchain_status": "Recorded",
        "timestamp": "2026-10-23 15:25:00 UTC",
        "recorded_block": "#0x8F91A099E",
    },
    {
        "id": "EV-005",
        "file_name": "tampered_artifact.log",
        "incident_id": "INC-TAMPER-TEST",
        # We intentionally record a historical hash that will NOT match after a modification!
        "stored_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "file_size": f"{tampered_file.stat().st_size} B",
        "blockchain_status": "Pending",
        "timestamp": "2026-10-23 18:00:00 UTC",
        "recorded_block": "#0x8F91A311F",
    },
]

catalog_file = EVIDENCE_DIR / "ledger_catalog.json"
catalog_file.write_text(json.dumps(evidence_catalog, indent=2), encoding="utf-8")
print(f"Initialized {len(evidence_catalog)} evidence artifacts with real SHA-256 hashes.")
