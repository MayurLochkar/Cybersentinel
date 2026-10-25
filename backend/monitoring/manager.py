"""
Monitoring Manager & Orchestration Engine for CyberSentinel-X.

Coordinates live network capture, PCAP file ingestion, feature extraction,
Random Forest ML inference, alert deduplication, and SQLite database persistence.
Accurately exposes capture modes (REAL live NIC sniffing, DEMO simulation, PCAP file ingestion),
packet and flow metrics, and actionable diagnostic status.
"""

from __future__ import annotations

import collections
import logging
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from database import engine
from ml.predict import predict_traffic, predict_traffic_batch
from models import Alert
from monitoring.flow_extractor import BiFlow
from monitoring.live_capture import LiveCaptureSession, is_pcap_available
from monitoring.pcap_processor import (
    process_pcap_bytes,
    process_pcap_file_streaming,
    validate_pcap_bytes,
    validate_pcap_file,
    PcapValidationError,
)

logger = logging.getLogger("cybersentinel.monitoring")


class MonitoringManager:
    """
    Thread-safe central coordinator for live network monitoring and PCAP telemetry ingestion.
    """

    def __init__(self, max_recent_flows: int = 100, dedup_window_seconds: float = 60.0):
        self._lock = threading.RLock()
        self.state: str = "STOPPED"          # STOPPED, STARTING, RUNNING, ERROR
        self.mode: str = "NONE"              # NONE, LIVE, PCAP
        self.capture_mode: str = "idle"      # idle, real, demo, pcap_file
        self.source: str = "None"
        self.selected_interface: Optional[str] = None
        self.started_at: Optional[str] = None
        self.last_activity: Optional[str] = None
        self.last_error: Optional[str] = None

        # Telemetry metrics
        self.total_packets_captured: int = 0
        self.flows_processed: int = 0
        self.benign_count: int = 0
        self.attack_count: int = 0
        self.alerts_created: int = 0
        self.errors_count: int = 0

        # Recent flow inspection buffer
        self.recent_flows: Deque[Dict[str, Any]] = collections.deque(maxlen=max_recent_flows)

        # Alert deduplication map: key -> last_alert_time
        self.dedup_window = dedup_window_seconds
        self._dedup_cache: Dict[str, float] = {}

        # Capture and Ingestion Session History Ledger
        self.session_history: List[Dict[str, Any]] = [
            {
                "session_id": "SES-BOOT-001",
                "type": "SYSTEM_START",
                "source": "Host Kernel & Ingress Pipeline",
                "interface": "All Adapters",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "packets_captured": 0,
                "flows_processed": 0,
                "attack_count": 0,
                "status": "INITIALIZED",
            }
        ]

        # Live capture session
        self._live_session: Optional[LiveCaptureSession] = None

        # Live PCAP ingestion progress tracker (supports 12+ GB files)
        self._abort_pcap_requested: bool = False
        self.pcap_progress: Dict[str, Any] = {
            "status": "idle",
            "filename": "",
            "file_size_mb": 0.0,
            "packets_read": 0,
            "flows_extracted": 0,
            "attack_flows": 0,
            "benign_flows": 0,
            "alerts_created": 0,
            "elapsed_seconds": 0.0,
            "current_rate_pps": 0.0,
            "error": None,
        }

    def get_pcap_progress(self) -> Dict[str, Any]:
        """Returns the current real-time PCAP parsing and classification progress."""
        with self._lock:
            return dict(self.pcap_progress)

    def stop_pcap_ingestion(self) -> Dict[str, Any]:
        """Signals active PCAP streaming to halt immediately."""
        with self._lock:
            self._abort_pcap_requested = True
            if self.pcap_progress.get("status") == "processing":
                self.pcap_progress["status"] = "stopped"
        return {"status": "success", "message": "PCAP streaming halted."}

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            # Sync with live session if running
            if self._live_session and self.state == "RUNNING":
                self.total_packets_captured = self._live_session.packets_captured
                if self._live_session.resolved_interface_name:
                    self.selected_interface = self._live_session.resolved_interface_name

                if not self._live_session.is_running:
                    if self._live_session.error_message:
                        self.state = "ERROR"
                        self.last_error = self._live_session.error_message
                    else:
                        self.state = "STOPPED"
                        self.capture_mode = "idle"

            is_running = (self.state == "RUNNING")
            pcap_capable = is_pcap_available()

            active_flows_count = len(self._live_session.aggregator.active_flows) if (self._live_session and self._live_session.aggregator) else 0
            dupes_prevented = self._live_session.aggregator.duplicates_prevented if (self._live_session and self._live_session.aggregator) else 0

            return {
                "status": self.state,
                "mode": self.mode,
                "capture_mode": self.capture_mode,
                "pcap_live_capable": pcap_capable,
                "is_running": is_running,
                "source": self.source,
                "selected_interface": self.selected_interface or self.source,
                "started_at": self.started_at,
                "last_activity": self.last_activity,
                "packets_captured": self.total_packets_captured,
                "flows_processed": self.flows_processed,
                "benign_count": self.benign_count,
                "attack_count": self.attack_count,
                "alerts_created": self.alerts_created,
                "alerts_generated": self.alerts_created,
                "active_flows_in_memory": active_flows_count,
                "duplicates_prevented": dupes_prevented,
                "errors_count": self.errors_count,
                "last_error": self.last_error,
            }

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            if self._live_session and self.state == "RUNNING":
                self.total_packets_captured = self._live_session.packets_captured
                if self._live_session.resolved_interface_name:
                    self.selected_interface = self._live_session.resolved_interface_name

            active_flows_count = len(self._live_session.aggregator.active_flows) if (self._live_session and self._live_session.aggregator) else 0
            dupes_prevented = self._live_session.aggregator.duplicates_prevented if (self._live_session and self._live_session.aggregator) else 0

            return {
                "status": self.state,
                "mode": self.mode,
                "capture_mode": self.capture_mode,
                "pcap_live_capable": is_pcap_available(),
                "is_running": (self.state == "RUNNING"),
                "source": self.source,
                "selected_interface": self.selected_interface or self.source,
                "packets_captured": self.total_packets_captured,
                "flows_processed": self.flows_processed,
                "benign_count": self.benign_count,
                "attack_count": self.attack_count,
                "alerts_created": self.alerts_created,
                "alerts_generated": self.alerts_created,
                "active_flows_in_memory": active_flows_count,
                "duplicates_prevented": dupes_prevented,
                "errors_count": self.errors_count,
                "last_error": self.last_error,
                "recent_flows": list(self.recent_flows),
            }

    def _should_create_alert(self, src_ip: str, dst_ip: str, dst_port: int, attack_label: str) -> bool:
        """Deduplicates alerts within the dedup window."""
        key = f"{src_ip}->{dst_ip}:{dst_port}_{attack_label}"
        now = time.time()

        cutoff = now - self.dedup_window
        self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v > cutoff}

        if key in self._dedup_cache:
            return False

        self._dedup_cache[key] = now
        return True

    def process_classified_flow(
        self,
        metadata: Dict[str, Any],
        features: Dict[str, float],
        mode: str = "LIVE",
        precomputed_prediction: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Classifies flow features with Random Forest and records alerts if ATTACK.
        Accepts precomputed_prediction to leverage high-speed vectorized batch inferences.
        """
        now_iso = datetime.now(timezone.utc).isoformat()

        if precomputed_prediction is not None:
            prediction_res = precomputed_prediction
        else:
            try:
                prediction_res = predict_traffic(features)
            except Exception as exc:
                with self._lock:
                    self.errors_count += 1
                    self.last_error = f"ML inference failed: {exc}"
                logger.error(f"Prediction failure: {exc}")
                return {
                    "error": str(exc),
                    "metadata": metadata,
                }

        pred_class = str(prediction_res.get("prediction", "BENIGN")).upper()
        confidence = float(prediction_res.get("confidence_percent", 0.0))
        probabilities = prediction_res.get("probabilities_percent", {})

        src_ip = metadata.get("source_ip", "0.0.0.0")
        dst_ip = metadata.get("destination_ip", "0.0.0.0")
        src_port = metadata.get("source_port", 0)
        dst_port = metadata.get("destination_port", 0)
        proto = metadata.get("protocol", "TCP")
        pkts = metadata.get("packet_count", 1)
        total_bytes = metadata.get("total_bytes", 0)
        duration_ms = metadata.get("duration_ms", 0.0)

        # Defensible protocol context analysis (RFC 2131 DHCP & Local Link Discovery)
        is_dhcp = (proto == "UDP" and ((src_port in (67, 68) and dst_port in (67, 68)) or (dst_ip in ("255.255.255.255", "0.0.0.0") and dst_port in (67, 68))))
        is_local_discovery = (proto == "UDP" and (dst_port in (5353, 5355, 1900) or dst_ip.startswith("224.0.0.") or dst_ip.startswith("239.255.")))
        protocol_context = None
        if is_dhcp:
            protocol_context = "DHCP Client Discovery (RFC 2131)"
        elif is_local_discovery:
            protocol_context = "Local Network Discovery (mDNS/LLMNR/SSDP)"

        alert_id: Optional[str] = None

        if pred_class == "ATTACK":
            with self._lock:
                self.attack_count += 1

            if self._should_create_alert(src_ip, dst_ip, dst_port, "ATTACK"):
                is_standard_discovery = (is_dhcp or is_local_discovery) and pkts <= 6

                if is_standard_discovery:
                    # Low-rate standard RFC discovery flows receiving ML ATTACK predictions
                    # are classified with LOW severity and explicit protocol context rather
                    # than false-alarm high/medium alerts.
                    severity = "LOW"
                    attack_type_label = "Network Protocol Anomaly (Unverified ML Prediction)"
                    reason_text = (
                        f"Authorized {mode} Ingestion: Broadcast UDP flow "
                        f"({src_ip}:{src_port} -> {dst_ip}:{dst_port}) "
                        f"received ML prediction ATTACK with {confidence:.1f}% confidence. "
                        f"Protocol matches standard {protocol_context}; flagged as unverified "
                        f"ML protocol anomaly due to training distribution variance."
                    )
                else:
                    if confidence >= 90.0:
                        severity = "CRITICAL"
                    elif confidence >= 75.0:
                        severity = "HIGH"
                    elif confidence >= 50.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"

                    attack_type_label = "Network Anomaly (ML Detection)"
                    reason_text = (
                        f"Authorized {mode} Ingestion: Suspicious {proto} flow "
                        f"({src_ip}:{src_port} -> {dst_ip}:{dst_port}) "
                        f"classified as ATTACK with {confidence:.1f}% confidence by Random Forest. "
                        f"Flow telemetry: {pkts} packets, {total_bytes} bytes over {duration_ms:.1f}ms."
                    )

                short_uid = uuid.uuid4().hex[:6].upper()
                timestamp_prefix = datetime.now(timezone.utc).strftime("%m%d%H%M")
                alert_id = f"INC-{mode[:4]}-{timestamp_prefix}-{short_uid}"

                try:
                    with Session(engine) as db:
                        new_alert = Alert(
                            incident_id=alert_id,
                            attack_type=attack_type_label,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            target=f"Port {dst_port} ({proto})",
                            severity=severity,
                            confidence=confidence,
                            status="Open",
                            reason=reason_text,
                            created_at=now_iso,
                        )
                        db.add(new_alert)
                        db.commit()

                    with self._lock:
                        self.alerts_created += 1
                except Exception as db_err:
                    logger.error(f"Failed to persist alert in SQLite: {db_err}")
        else:
            with self._lock:
                self.benign_count += 1

        with self._lock:
            self.flows_processed += 1
            self.last_activity = now_iso

            # Extract source packet timestamps and capture origin diagnostics
            pkt_start_iso = metadata.get("packet_start_time") or metadata.get("start_time") or now_iso
            pkt_end_iso = metadata.get("packet_end_time") or metadata.get("last_time") or now_iso
            pkt_start_epoch = float(metadata.get("packet_start_epoch", time.time()))
            pkt_end_epoch = float(metadata.get("packet_end_epoch", time.time()))
            capture_origin = metadata.get("capture_origin") or ("npcap_live_nic" if self.capture_mode == "real" else ("demo_simulation" if self.capture_mode == "demo" else self.capture_mode))
            interface_used = metadata.get("interface") or self.selected_interface or self.source
            close_reason = metadata.get("close_reason", "completed")

            flow_record = {
                "id": str(uuid.uuid4())[:8],
                "timestamp": pkt_end_iso,  # Authentic packet timestamp
                "packet_start_time": pkt_start_iso,
                "packet_end_time": pkt_end_iso,
                "packet_start_epoch": pkt_start_epoch,
                "packet_end_epoch": pkt_end_epoch,
                "capture_origin": capture_origin,
                "interface": interface_used,
                "close_reason": close_reason,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": proto,
                "packets": pkts,
                "bytes": total_bytes,
                "duration_ms": duration_ms,
                "prediction": pred_class,
                "confidence": confidence,
                "probabilities": probabilities,
                "alert_id": alert_id,
                "mode": mode,
            }
            self.recent_flows.appendleft(flow_record)

        return flow_record

    def _handle_live_biflow(self, flow: BiFlow) -> None:
        """Callback for live sniffer when a flow completes."""
        try:
            meta = flow.get_metadata()
            feats = flow.compute_features()
            self.process_classified_flow(meta, feats, mode="LIVE")
        except Exception as exc:
            logger.error(f"Error processing live flow: {exc}")

    def start_monitoring(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        mode: str = "real",
        reset_counters: bool = True,
    ) -> Dict[str, Any]:
        """
        Starts live monitoring.
        - mode='real': genuine promiscuous sniffing on the physical/virtual adapter via Npcap.
        - mode='demo': explicit synthetic telemetry generation for test purposes only.
        """
        requested_mode = mode.lower().strip()
        if requested_mode not in ("real", "demo"):
            raise ValueError(f"Invalid mode '{mode}'. Must be 'real' or 'demo'.")

        with self._lock:
            if self.state == "RUNNING":
                return {
                    "status": "already_running",
                    "message": f"Monitoring is already running on {self.source}",
                    "capture_mode": self.capture_mode,
                }

            if requested_mode == "real" and not is_pcap_available():
                raise RuntimeError(
                    "Npcap packet capture driver is not available or inactive on this Windows host. "
                    "Genuine live packet sniffing requires Npcap (https://npcap.com) with "
                    "WinPcap API-compatible mode enabled. Real live capture will not silently simulate traffic."
                )

            self.state = "STARTING"
            self.mode = "LIVE"
            self.capture_mode = requested_mode
            if requested_mode == "real":
                self.source = interface or "Auto-Detect Default"
            else:
                self.source = f"{interface or 'Simulated Engine'} (DEMO MODE)"
            self.selected_interface = interface
            self.last_error = None

            if reset_counters:
                self.total_packets_captured = 0
                self.flows_processed = 0
                self.benign_count = 0
                self.attack_count = 0
                self.recent_flows.clear()

        try:
            session = LiveCaptureSession(
                interface=interface,
                bpf_filter=bpf_filter,
                flow_callback=self._handle_live_biflow,
                capture_mode=requested_mode,
            )
            session.start()

            with self._lock:
                self._live_session = session
                self.state = "RUNNING"
                self.selected_interface = session.resolved_interface_name or self.source
                self.started_at = datetime.now(timezone.utc).isoformat()
                self.last_activity = self.started_at

                session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"
                self.session_history.append({
                    "session_id": session_id,
                    "type": "REAL_LIVE_NIC" if requested_mode == "real" else "DEMO_SIMULATION",
                    "source": self.source,
                    "interface": self.selected_interface,
                    "started_at": self.started_at,
                    "ended_at": None,
                    "packets_captured": 0,
                    "flows_processed": 0,
                    "attack_count": 0,
                    "status": "RUNNING",
                })

            return {
                "status": "started",
                "capture_mode": requested_mode,
                "source": self.source,
                "selected_interface": self.selected_interface,
                "started_at": self.started_at,
            }
        except Exception as exc:
            with self._lock:
                self.state = "ERROR"
                self.capture_mode = "idle"
                self.last_error = str(exc)
            logger.error(f"Failed to start live capture: {exc}")
            raise

    def stop_monitoring(self) -> Dict[str, Any]:
        with self._lock:
            if self.state != "RUNNING" and not self._live_session:
                return {
                    "status": "already_stopped",
                    "message": "Monitoring is not currently active.",
                }

            session = self._live_session
            self._live_session = None
            self.state = "STOPPED"
            self.capture_mode = "idle"

            # Update running session in history
            for s in reversed(self.session_history):
                if s.get("status") == "RUNNING":
                    s["ended_at"] = datetime.now(timezone.utc).isoformat()
                    s["packets_captured"] = self.total_packets_captured
                    s["flows_processed"] = self.flows_processed
                    s["attack_count"] = self.attack_count
                    s["status"] = "COMPLETED"
                    break

        if session:
            self.total_packets_captured = session.packets_captured
            session.stop()

        return {
            "status": "stopped",
            "message": "Monitoring stopped cleanly.",
            "packets_captured": self.total_packets_captured,
            "flows_processed": self.flows_processed,
            "alerts_created": self.alerts_created,
        }

    def ingest_pcap_file_path(
        self,
        filepath: Union[str, Path],
        filename: Optional[str] = None,
        max_packets: Optional[int] = None,
        flow_timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """
        Streams and parses a PCAP file directly from disk.
        Processes flows in bounded batches with real-time classification,
        guaranteeing zero RAM exhaustion even for 12+ GB capture files.
        """
        path_obj = Path(filepath)
        display_name = filename or path_obj.name
        file_size_mb = round(path_obj.stat().st_size / (1024 * 1024), 2)

        with self._lock:
            self.mode = "PCAP"
            self.capture_mode = "pcap_file"
            self.source = f"File: {display_name} ({file_size_mb} MB)"
            self.selected_interface = f"PCAP: {display_name}"
            self.last_error = None
            self._abort_pcap_requested = False
            self.pcap_progress = {
                "status": "processing",
                "filename": display_name,
                "file_size_mb": file_size_mb,
                "packets_read": 0,
                "flows_extracted": 0,
                "attack_flows": 0,
                "benign_flows": 0,
                "alerts_created": 0,
                "elapsed_seconds": 0.0,
                "current_rate_pps": 0.0,
                "error": None,
            }

        processed = 0
        benigns = 0
        attacks = 0
        alerts = 0

        def on_batch(flows_batch: List[Tuple[Dict[str, Any], Dict[str, float]]]):
            nonlocal processed, benigns, attacks, alerts
            if not flows_batch:
                return

            feats_list = [f[1] for f in flows_batch]
            try:
                batch_preds = predict_traffic_batch(feats_list)
            except Exception:
                batch_preds = [None] * len(flows_batch)

            for (meta, feats), pred in zip(flows_batch, batch_preds):
                res = self.process_classified_flow(
                    meta,
                    feats,
                    mode="PCAP",
                    precomputed_prediction=pred,
                )
                if "error" in res or res.get("prediction") is None:
                    continue
                processed += 1
                if res.get("prediction") == "ATTACK":
                    attacks += 1
                    if res.get("alert_id"):
                        alerts += 1
                elif res.get("prediction") == "BENIGN":
                    benigns += 1

            with self._lock:
                self.pcap_progress["flows_extracted"] = processed
                self.pcap_progress["attack_flows"] = attacks
                self.pcap_progress["benign_flows"] = benigns
                self.pcap_progress["alerts_created"] = alerts

        def on_progress(prog_dict: Dict[str, Any]):
            with self._lock:
                self.pcap_progress.update(prog_dict)
                self.pcap_progress["flows_extracted"] = processed
                self.pcap_progress["attack_flows"] = attacks
                self.pcap_progress["benign_flows"] = benigns
                self.pcap_progress["alerts_created"] = alerts

        try:
            summary = process_pcap_file_streaming(
                filepath=path_obj,
                filename=display_name,
                flow_timeout=flow_timeout,
                max_packets=max_packets,
                batch_flow_callback=on_batch,
                progress_callback=on_progress,
                abort_check=lambda: self._abort_pcap_requested,
            )
        except Exception as exc:
            with self._lock:
                self.pcap_progress["status"] = "error"
                self.pcap_progress["error"] = str(exc)
                self.last_error = str(exc)
            raise

        with self._lock:
            self.pcap_progress["status"] = "completed"
            self.pcap_progress["elapsed_seconds"] = summary["elapsed_seconds"]
            self.pcap_progress["packets_read"] = summary["packets_read"]
            self.pcap_progress["flows_extracted"] = processed
            self.pcap_progress["attack_flows"] = attacks
            self.pcap_progress["benign_flows"] = benigns
            self.pcap_progress["alerts_created"] = alerts

            self.session_history.append({
                "session_id": f"PCAP-{uuid.uuid4().hex[:8].upper()}",
                "type": "PCAP_INGESTION",
                "source": display_name,
                "interface": f"PCAP Stream ({file_size_mb} MB)",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "packets_captured": summary["packets_read"],
                "flows_processed": processed,
                "attack_count": attacks,
                "status": "COMPLETED",
            })
            if len(self.session_history) > 100:
                self.session_history = self.session_history[-100:]

        return {
            "status": "success",
            "filename": display_name,
            "file_size_mb": file_size_mb,
            "packets_processed": summary["packets_read"],
            "flows_extracted": processed,
            "benign_flows": benigns,
            "attack_flows": attacks,
            "alerts_created": alerts,
            "elapsed_seconds": summary["elapsed_seconds"],
        }

    def ingest_pcap(self, pcap_data: bytes, filename: str) -> Dict[str, Any]:
        """
        Parses authorized PCAP file bytes, classifies flows, and saves alerts.
        Streams through a temporary file to guarantee bounded memory usage.
        """
        validate_pcap_bytes(pcap_data, filename)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(pcap_data)
            tmp_path = tmp.name

        try:
            return self.ingest_pcap_file_path(tmp_path, filename=filename)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def reset_counters(self) -> Dict[str, Any]:
        """
        Resets all live telemetry counters and flow buffers to 0, and records milestone in history.
        """
        with self._lock:
            old_flows = self.flows_processed
            old_pkts = self.total_packets_captured

            self.total_packets_captured = 0
            self.flows_processed = 0
            self.benign_count = 0
            self.attack_count = 0
            self.alerts_created = 0
            self.errors_count = 0
            self.recent_flows.clear()
            self._dedup_cache.clear()

            if self._live_session:
                self._live_session.packets_captured = 0
                if self._live_session.aggregator:
                    self._live_session.aggregator.active_flows.clear()
                    self._live_session.aggregator.recently_closed.clear()
                    self._live_session.aggregator.duplicates_prevented = 0

            self.session_history.append({
                "session_id": f"RST-{uuid.uuid4().hex[:8].upper()}",
                "type": "TELEMETRY_RESET",
                "source": "Manual Analyst Reset",
                "interface": self.selected_interface or "All Adapters",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "ended_at": datetime.now(timezone.utc).isoformat(),
                "packets_captured": old_pkts,
                "flows_processed": old_flows,
                "attack_count": 0,
                "status": "COUNTERS_ZEROED",
            })

            return self.get_status()

    def get_session_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self.session_history))

    def clear_session_history(self) -> Dict[str, str]:
        with self._lock:
            self.session_history.clear()
            return {"status": "cleared", "message": "Session history cleared."}


# Global singleton manager instance
monitoring_manager = MonitoringManager()
