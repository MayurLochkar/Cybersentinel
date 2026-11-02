"""
CyberSentinel-X - Live Connection Window Anomaly Detector & Diagnostic Tracker.
================================================================================
Monitors live packet traffic, tracks incomplete TCP handshakes, measures connection
velocity across sliding time windows, and detects single-source DoS patterns without
forcing or falsifying ML model weights.

Strict Grounding Rules:
- Distinguishes baseline traffic (low rate, completed handshakes) from DoS simulations.
- Strictly labels single-IP traffic bursts as 'SUSPECTED Single-Source DoS', NEVER 'CONFIRMED DDoS'.
- Exposes observable diagnostic metrics: packets captured, host-addressed packets,
  Laptop B packets, incomplete SYN flows, flows created/closed, and classification passes.
"""

from __future__ import annotations

import collections
import logging
import socket
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("cybersentinel.anomaly_detector")


def get_runtime_host_ips() -> Set[str]:
    """Dynamically resolves all active local IPv4 and IPv6 addresses for the host machine."""
    ips: Set[str] = {"127.0.0.1", "::1", "localhost"}
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("169.254"):
                ips.add(ip)
    except Exception:
        pass
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            raw_ip = str(item[4][0])
            if raw_ip and not raw_ip.startswith("fe80"):
                ips.add(raw_ip)
    except Exception:
        pass
    return ips


class LiveAnomalyDetector:
    """
    Thread-safe live anomaly detection engine and diagnostic counter ledger.
    Tracks TCP connection velocity, incomplete handshakes, and diagnostic metrics.
    """

    def __init__(
        self,
        window_seconds: float = 6.0,
        syn_burst_threshold: int = 4,
        connection_rate_threshold: float = 3.0,
    ):
        self._lock = threading.RLock()
        self.window_seconds = window_seconds
        self.syn_burst_threshold = syn_burst_threshold
        self.connection_rate_threshold = connection_rate_threshold

        # Host and Client IP Discovery
        self.host_ips: Set[str] = get_runtime_host_ips()
        self.laptop_b_ip: Optional[str] = None

        # Diagnostic Counters (Requirement 3)
        self.packets_received_total: int = 0
        self.packets_addressed_to_host: int = 0
        self.packets_from_laptop_b: int = 0
        self.flows_created: int = 0
        self.flows_closed: int = 0
        self.incomplete_syn_flows: int = 0
        self.flows_passed_to_classifier: int = 0
        self.alerts_written_to_db: int = 0

        # Last captured packet snapshot for live UI / API inspection
        self.last_packet_snapshot: Optional[Dict[str, Any]] = None

        # Sliding Window Records: src_ip -> deque of (timestamp, dst_ip, dst_port, flags)
        self._connection_windows: Dict[str, Deque[Tuple[float, str, int, int]]] = collections.defaultdict(
            lambda: collections.deque(maxlen=2000)
        )

        # Active Anomaly State: src_ip -> last_anomaly_dict
        self._active_anomalies: Dict[str, Dict[str, Any]] = {}
        self._last_alert_time: Dict[str, float] = {}
        self.alert_cooldown_seconds: float = 4.0

        # Active Attack State Tracking (distinguishes Attack in progress from Normal / Safe)
        self.last_attack_timestamp: float = 0.0
        self.last_attack_type: Optional[str] = None
        self.last_attacker_ip: Optional[str] = None
        self.last_attack_severity: Optional[str] = None

        # Alert callback for real-time immediate notifications
        self.on_anomaly_alert: Optional[Any] = None

    def refresh_host_ips(self) -> Set[str]:
        with self._lock:
            self.host_ips = get_runtime_host_ips()
            return set(self.host_ips)

    def set_laptop_b_ip(self, ip: str) -> None:
        with self._lock:
            clean = ip.strip()
            if clean and clean not in self.host_ips and clean not in ("127.0.0.1", "::1", "localhost"):
                self.laptop_b_ip = clean
                logger.info(f"AnomalyDetector: Explicitly assigned Laptop B IP: {clean}")

    def record_attack_detected(self, attack_type: str, src_ip: str, severity: str = "CRITICAL") -> None:
        """Records an active attack event with timestamp for real-time live alert state."""
        with self._lock:
            self.last_attack_timestamp = time.time()
            self.last_attack_type = attack_type
            self.last_attacker_ip = src_ip
            self.last_attack_severity = severity
            if src_ip not in self.host_ips and src_ip not in ("127.0.0.1", "::1", "localhost") and not src_ip.endswith(".1") and not src_ip.endswith(".254"):
                self.set_laptop_b_ip(src_ip)
            elif self.laptop_b_ip is None:
                self.set_laptop_b_ip(src_ip)
            logger.info(f"AnomalyDetector: Active attack registered: {attack_type} from {src_ip} ({severity})")

    def clear_active_attack(self) -> None:
        """Resets active attack state to NORMAL / SAFE."""
        with self._lock:
            self.last_attack_timestamp = 0.0
            self.last_attack_type = None
            self.last_attacker_ip = None
            self.last_attack_severity = None
            self._active_anomalies.clear()
            logger.info("AnomalyDetector: Active attack cleared. System returned to NORMAL state.")

    def get_active_attack_state(self, active_window_seconds: float = 25.0) -> Dict[str, Any]:
        """
        Returns whether an attack has been detected within active_window_seconds.
        When no attack has occurred within this window, returns is_active_attack=False, NORMAL.
        """
        with self._lock:
            now = time.time()
            is_active = (self.last_attack_timestamp > 0.0) and ((now - self.last_attack_timestamp) <= active_window_seconds)
            seconds_ago = round(now - self.last_attack_timestamp, 1) if self.last_attack_timestamp > 0.0 else None
            return {
                "is_active_attack": is_active,
                "current_threat_level": (self.last_attack_severity or "CRITICAL") if is_active else "NORMAL",
                "active_attack_type": self.last_attack_type if is_active else None,
                "active_attack_source": self.last_attacker_ip if is_active else None,
                "last_attack_timestamp": self.last_attack_timestamp if self.last_attack_timestamp > 0.0 else None,
                "last_attack_seconds_ago": seconds_ago if is_active else None,
            }

    def reset_diagnostics(self) -> None:
        """Resets all packet and flow counters."""
        with self._lock:
            self.laptop_b_ip = None
            self.packets_received_total = 0
            self.packets_addressed_to_host = 0
            self.packets_from_laptop_b = 0
            self.flows_created = 0
            self.flows_closed = 0
            self.incomplete_syn_flows = 0
            self.flows_passed_to_classifier = 0
            self.alerts_written_to_db = 0
            self.last_packet_snapshot = None
            self._connection_windows.clear()
            self._active_anomalies.clear()
            self._last_alert_time.clear()
            self.clear_active_attack()

    def record_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        flags: int,
        timestamp: float,
        payload_len: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """
        Records an ingested network packet, updates diagnostic metrics, and
        evaluates live connection burst velocity.
        """
        with self._lock:
            self.packets_received_total += 1

            # 1. Intrusion Prevention & Firewall Blocklist Enforcement
            from monitoring.firewall_blocklist import firewall_blocklist
            if firewall_blocklist.is_blocked(src_ip):
                dropped_count = firewall_blocklist.record_dropped_packet(src_ip, dst_port)
                self.last_packet_snapshot = {
                    "timestamp": timestamp,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": src_port,
                    "destination_port": dst_port,
                    "protocol": proto,
                    "flags": flags,
                    "firewall_action": "BLOCKED_DROPPED",
                    "dropped_count": dropped_count,
                }
                # Blocked traffic is safely dropped at perimeter; no alert is generated.
                return {
                    "is_anomaly": False,
                    "is_blocked": True,
                    "firewall_action": "DROPPED",
                    "source_ip": src_ip,
                    "dropped_count": dropped_count,
                    "message": f"Inbound packet from {src_ip} intercepted and dropped by active firewall rule.",
                }

            # Check if addressed to Laptop A
            if dst_ip in self.host_ips:
                self.packets_addressed_to_host += 1

            # Auto-discover or match Laptop B IP
            is_client_candidate = (
                src_ip not in self.host_ips
                and src_ip != "127.0.0.1"
                and not src_ip.startswith("169.254")
                and not src_ip.endswith(".1")
                and not src_ip.endswith(".254")
                and (src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."))
            )
            if is_client_candidate and (dst_port in (8000, 8080, 8888, 9999) or self.laptop_b_ip is None):
                if self.laptop_b_ip != src_ip:
                    self.laptop_b_ip = src_ip
                    logger.info(f"AnomalyDetector: Dynamically bound Laptop B test source to: {src_ip}")

            if self.laptop_b_ip and src_ip == self.laptop_b_ip:
                self.packets_from_laptop_b += 1

            self.last_packet_snapshot = {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "protocol": proto,
                "flags": flags,
            }

            # Only evaluate TCP connections for SYN/DoS velocity
            if proto.upper() != "TCP":
                return None

            # Only evaluate INBOUND connection attempts targeting Laptop A's ports or host IPs,
            # and strictly ignore ordinary outbound browser traffic originating from Laptop A itself.
            is_outbound_from_host = (src_ip in self.host_ips or src_ip in ("127.0.0.1", "::1", "localhost"))
            is_inbound_target = (dst_ip in self.host_ips or dst_port in (8000, 8080, 80, 8888, 9999))
            if is_outbound_from_host or not is_inbound_target:
                return None

            is_syn = bool(flags & 0x02)
            is_ack = bool(flags & 0x10)
            is_from_b = bool(self.laptop_b_ip and src_ip == self.laptop_b_ip)

            # Record only incomplete TCP SYN connection attempts (without ACK)
            if is_syn and not is_ack:
                dq = self._connection_windows[src_ip]
                dq.append((timestamp, dst_ip, dst_port, flags))

                # Prune old records outside sliding window
                cutoff = timestamp - self.window_seconds
                while dq and dq[0][0] < cutoff:
                    dq.popleft()

                window_count = len(dq)
                conn_rate = window_count / self.window_seconds

                # Count distinct target ports
                target_ports = {item[2] for item in dq}
                is_single_port_target = len(target_ports) <= 2

                # Evaluate Single-Source DoS Burst:
                # High velocity (>= 3.0 conn/s) or sustained accumulation (>= 8 incomplete SYNs in window).
                # Ordinary baseline traffic (<= 1.0 conn/s, completed handshakes) produces ZERO alerts.
                is_burst = (window_count >= 8) or (window_count >= self.syn_burst_threshold and conn_rate >= self.connection_rate_threshold)

                if is_burst and is_single_port_target:
                    last_alert = self._last_alert_time.get(src_ip, 0.0)
                    if (timestamp - last_alert) >= self.alert_cooldown_seconds:
                        self._last_alert_time[src_ip] = timestamp
                        primary_port = target_ports.pop() if target_ports else dst_port
                        anomaly_info = {
                            "is_anomaly": True,
                            "anomaly_type": "Single-Source DoS (SYN Flood / Connection Exhaustion)",
                            "subtype_status": "SUSPECTED",
                            "severity": "CRITICAL" if (conn_rate >= 5.0 or is_from_b) else "HIGH",
                            "source_ip": src_ip,
                            "destination_ip": dst_ip,
                            "destination_port": primary_port,
                            "protocol": "TCP",
                            "connection_rate": round(conn_rate, 1),
                            "incomplete_handshakes": window_count,
                            "window_seconds": self.window_seconds,
                            "confidence": min(95.0, round(70.0 + (window_count * 0.5), 1)),
                            "rationale": (
                                f"Rapid connection burst: {window_count} incomplete TCP SYN connection attempts "
                                f"at {conn_rate:.1f} conn/s over a {self.window_seconds:.1f}s window targeting Port {primary_port}. "
                                f"Originates from single host {src_ip} (Single-Source DoS simulation, not distributed DDoS)."
                            ),
                            "evidence_needed": "Target server TCP backlog (netstat / ss) and edge firewall SYN drop audit.",
                        }
                        self._active_anomalies[src_ip] = anomaly_info
                        self.record_attack_detected(
                            anomaly_info["anomaly_type"],
                            src_ip,
                            anomaly_info["severity"]
                        )

                        if self.on_anomaly_alert:
                            try:
                                self.on_anomaly_alert(anomaly_info)
                            except Exception as cb_err:
                                logger.debug(f"Anomaly alert callback error: {cb_err}")

                        return anomaly_info

        return None

    def get_window_context_for_flow(self, src_ip: str) -> Optional[Dict[str, Any]]:
        """Returns active anomaly window context for a specific source IP if present."""
        with self._lock:
            return self._active_anomalies.get(src_ip)

    def record_flow_created(self) -> None:
        with self._lock:
            self.flows_created += 1

    def record_flow_closed(self, is_incomplete_syn: bool = False) -> None:
        with self._lock:
            self.flows_closed += 1
            if is_incomplete_syn:
                self.incomplete_syn_flows += 1

    def record_flow_classified(self) -> None:
        with self._lock:
            self.flows_passed_to_classifier += 1

    def record_alert_written(self) -> None:
        with self._lock:
            self.alerts_written_to_db += 1

    def get_diagnostics(self) -> Dict[str, Any]:
        """Returns comprehensive diagnostic telemetry report (Requirement 3)."""
        with self._lock:
            active_state = self.get_active_attack_state()
            diag = {
                "host_ips": sorted(list(self.host_ips)),
                "laptop_b_ip": self.laptop_b_ip or "Auto-detecting on first packet",
                "packets_received_total": self.packets_received_total,
                "packets_addressed_to_host": self.packets_addressed_to_host,
                "packets_from_laptop_b": self.packets_from_laptop_b,
                "flows_created": self.flows_created,
                "flows_closed": self.flows_closed,
                "incomplete_syn_flows": self.incomplete_syn_flows,
                "flows_passed_to_classifier": self.flows_passed_to_classifier,
                "alerts_written_to_db": self.alerts_written_to_db,
                "active_anomalies": list(self._active_anomalies.values()),
                "last_packet_snapshot": self.last_packet_snapshot,
            }
            diag.update(active_state)

            from monitoring.firewall_blocklist import firewall_blocklist
            fw_stats = firewall_blocklist.get_stats()
            diag["firewall_blocked_ips"] = fw_stats["blocked_ips"]
            diag["firewall_dropped_packets"] = fw_stats["total_dropped_packets"]
            diag["firewall_shield_active"] = fw_stats["status"] == "ACTIVE"
            return diag


# Global singleton instance
anomaly_detector = LiveAnomalyDetector()
