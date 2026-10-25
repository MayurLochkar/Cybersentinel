"""
Bidirectional Network Flow Aggregator and CICIDS2017 Feature Extractor.

Accurately converts raw network packets (from PCAP captures or live packet sniffing)
into bidirectional network flows and computes the exact 70 numeric features expected
by the CyberSentinel-X CICIDS2017 Random Forest classifier.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _safe_mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _safe_std(values: List[float], mean: Optional[float] = None) -> float:
    if len(values) < 2:
        return 0.0
    if mean is None:
        mean = _safe_mean(values)
    variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
    return float(math.sqrt(max(0.0, variance)))


def _safe_variance(values: List[float], mean: Optional[float] = None) -> float:
    if len(values) < 2:
        return 0.0
    if mean is None:
        mean = _safe_mean(values)
    return float(max(0.0, sum((x - mean) ** 2 for x in values) / (len(values) - 1)))


@dataclass
class PacketRecord:
    timestamp: float  # Epoch timestamp in seconds
    length: int       # Total IP packet length in bytes
    payload_len: int  # Transport payload length
    header_len: int   # Transport + IP header length
    is_fwd: bool      # True if forward direction, False if backward
    flags: int = 0    # TCP flags bitmask
    window_size: int = 0
    has_payload: bool = False


class BiFlow:
    """
    Tracks a bidirectional flow between two endpoints.
    Forward direction is defined by the first observed packet in the flow.
    """

    def __init__(
        self,
        fwd_ip: str,
        fwd_port: int,
        bwd_ip: str,
        bwd_port: int,
        protocol: str,
        start_time: float,
        capture_origin: str = "npcap_live_nic",
        interface: str = "",
    ):
        self.fwd_ip = fwd_ip
        self.fwd_port = fwd_port
        self.bwd_ip = bwd_ip
        self.bwd_port = bwd_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_time = start_time
        self.capture_origin = capture_origin
        self.interface = interface
        self.close_reason = "in_progress"

        self.fwd_packets: List[PacketRecord] = []
        self.bwd_packets: List[PacketRecord] = []
        self.all_packets: List[PacketRecord] = []

        self.init_win_fwd: int = -1
        self.init_win_bwd: int = -1

        # TCP Connection Teardown Tracking
        self.fwd_fin: bool = False
        self.bwd_fin: bool = False
        self.rst_seen: bool = False
        self.is_closed: bool = False

    def add_packet(
        self,
        timestamp: float,
        length: int,
        payload_len: int,
        header_len: int,
        is_fwd: bool,
        flags: int = 0,
        window_size: int = 0,
    ) -> None:
        has_payload = payload_len > 0
        record = PacketRecord(
            timestamp=timestamp,
            length=length,
            payload_len=payload_len,
            header_len=header_len,
            is_fwd=is_fwd,
            flags=flags,
            window_size=window_size,
            has_payload=has_payload,
        )

        self.all_packets.append(record)
        if is_fwd:
            self.fwd_packets.append(record)
            if self.init_win_fwd == -1 and window_size > 0:
                self.init_win_fwd = window_size
            if flags & 0x01:  # FIN flag
                self.fwd_fin = True
        else:
            self.bwd_packets.append(record)
            if self.init_win_bwd == -1 and window_size > 0:
                self.init_win_bwd = window_size
            if flags & 0x01:  # FIN flag
                self.bwd_fin = True

        self.last_time = max(self.last_time, timestamp)

        # Robust TCP connection state evaluation:
        # RST terminates abruptly. Bidirectional FIN indicates full graceful teardown.
        if flags & 0x04:  # RST flag
            self.rst_seen = True
            self.is_closed = True
            self.close_reason = "tcp_rst"
        elif self.fwd_fin and self.bwd_fin:
            self.is_closed = True
            self.close_reason = "tcp_fin_handshake"

    def compute_features(self) -> Dict[str, float]:
        """
        Computes the exact 70 CICIDS2017 flow features.
        """
        # Duration in microseconds
        duration_sec = max(0.0, self.last_time - self.start_time)
        flow_duration_us = float(duration_sec * 1_000_000.0)

        total_fwd_pkts = len(self.fwd_packets)
        total_bwd_pkts = len(self.bwd_packets)
        total_pkts = len(self.all_packets)

        fwd_lengths = [p.length for p in self.fwd_packets]
        bwd_lengths = [p.length for p in self.bwd_packets]
        all_lengths = [p.length for p in self.all_packets]

        total_len_fwd = float(sum(fwd_lengths))
        total_len_bwd = float(sum(bwd_lengths))
        total_bytes = total_len_fwd + total_len_bwd

        # Forward Packet Length stats
        fwd_len_max = float(max(fwd_lengths)) if fwd_lengths else 0.0
        fwd_len_min = float(min(fwd_lengths)) if fwd_lengths else 0.0
        fwd_len_mean = _safe_mean([float(x) for x in fwd_lengths])
        fwd_len_std = _safe_std([float(x) for x in fwd_lengths], fwd_len_mean)

        # Backward Packet Length stats
        bwd_len_max = float(max(bwd_lengths)) if bwd_lengths else 0.0
        bwd_len_min = float(min(bwd_lengths)) if bwd_lengths else 0.0
        bwd_len_mean = _safe_mean([float(x) for x in bwd_lengths])
        bwd_len_std = _safe_std([float(x) for x in bwd_lengths], bwd_len_mean)

        # Rate calculations (using seconds, avoid div by 0)
        dur_divisor = duration_sec if duration_sec > 1e-6 else 1.0
        flow_bytes_s = float(total_bytes / dur_divisor) if duration_sec > 1e-6 else 0.0
        flow_pkts_s = float(total_pkts / dur_divisor) if duration_sec > 1e-6 else 0.0
        fwd_pkts_s = float(total_fwd_pkts / dur_divisor) if duration_sec > 1e-6 else 0.0
        bwd_pkts_s = float(total_bwd_pkts / dur_divisor) if duration_sec > 1e-6 else 0.0

        # Inter-arrival times (IAT) in microseconds
        def calc_iats(packets: List[PacketRecord]) -> List[float]:
            if len(packets) < 2:
                return []
            return [
                max(0.0, (packets[i].timestamp - packets[i - 1].timestamp) * 1_000_000.0)
                for i in range(1, len(packets))
            ]

        flow_iats = calc_iats(self.all_packets)
        flow_iat_mean = _safe_mean(flow_iats)
        flow_iat_std = _safe_std(flow_iats, flow_iat_mean)
        flow_iat_max = float(max(flow_iats)) if flow_iats else 0.0
        flow_iat_min = float(min(flow_iats)) if flow_iats else 0.0

        fwd_iats = calc_iats(self.fwd_packets)
        fwd_iat_total = float(sum(fwd_iats))
        fwd_iat_mean = _safe_mean(fwd_iats)
        fwd_iat_std = _safe_std(fwd_iats, fwd_iat_mean)
        fwd_iat_max = float(max(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_min = float(min(fwd_iats)) if fwd_iats else 0.0

        bwd_iats = calc_iats(self.bwd_packets)
        bwd_iat_total = float(sum(bwd_iats))
        bwd_iat_mean = _safe_mean(bwd_iats)
        bwd_iat_std = _safe_std(bwd_iats, bwd_iat_mean)
        bwd_iat_max = float(max(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_min = float(min(bwd_iats)) if bwd_iats else 0.0

        # TCP Flag Counts (Bitwise mask: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWE=0x80)
        fwd_psh_flags = float(sum(1 for p in self.fwd_packets if (p.flags & 0x08)))
        fwd_urg_flags = float(sum(1 for p in self.fwd_packets if (p.flags & 0x20)))

        fin_count = float(sum(1 for p in self.all_packets if (p.flags & 0x01)))
        syn_count = float(sum(1 for p in self.all_packets if (p.flags & 0x02)))
        rst_count = float(sum(1 for p in self.all_packets if (p.flags & 0x04)))
        psh_count = float(sum(1 for p in self.all_packets if (p.flags & 0x08)))
        ack_count = float(sum(1 for p in self.all_packets if (p.flags & 0x10)))
        urg_count = float(sum(1 for p in self.all_packets if (p.flags & 0x20)))
        ece_count = float(sum(1 for p in self.all_packets if (p.flags & 0x40)))
        cwe_count = float(sum(1 for p in self.all_packets if (p.flags & 0x80)))

        # Header lengths
        fwd_header_len = float(sum(p.header_len for p in self.fwd_packets))
        bwd_header_len = float(sum(p.header_len for p in self.bwd_packets))

        # Overall Packet Length stats
        min_pkt_len = float(min(all_lengths)) if all_lengths else 0.0
        max_pkt_len = float(max(all_lengths)) if all_lengths else 0.0
        pkt_len_mean = _safe_mean([float(x) for x in all_lengths])
        pkt_len_std = _safe_std([float(x) for x in all_lengths], pkt_len_mean)
        pkt_len_var = _safe_variance([float(x) for x in all_lengths], pkt_len_mean)

        # Down/Up Ratio
        down_up_ratio = float(total_bwd_pkts / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0

        # Segment & packet size averages
        avg_pkt_size = float(total_bytes / total_pkts) if total_pkts > 0 else 0.0
        avg_fwd_seg_size = fwd_len_mean
        avg_bwd_seg_size = bwd_len_mean

        # Subflow features (for standard flows, equals overall flow)
        subflow_fwd_pkts = float(total_fwd_pkts)
        subflow_fwd_bytes = total_len_fwd
        subflow_bwd_pkts = float(total_bwd_pkts)
        subflow_bwd_bytes = total_len_bwd

        # Window sizes & active data packets
        init_win_fwd = float(self.init_win_fwd if self.init_win_fwd >= 0 else 0.0)
        init_win_bwd = float(self.init_win_bwd if self.init_win_bwd >= 0 else 0.0)
        act_data_pkt_fwd = float(sum(1 for p in self.fwd_packets if p.has_payload))

        # Minimum segment size forward (transport header length)
        fwd_header_lens = [p.header_len for p in self.fwd_packets if p.header_len > 0]
        min_seg_size_fwd = float(min(fwd_header_lens)) if fwd_header_lens else 20.0

        # Active & Idle periods (Threshold: 5,000,000 microseconds = 5.0 seconds)
        idle_threshold_us = 5_000_000.0
        idle_times: List[float] = []
        active_times: List[float] = []

        cur_active_start = self.all_packets[0].timestamp if self.all_packets else 0.0
        cur_active_end = cur_active_start

        for i in range(1, len(self.all_packets)):
            gap_us = (self.all_packets[i].timestamp - self.all_packets[i - 1].timestamp) * 1_000_000.0
            if gap_us > idle_threshold_us:
                idle_times.append(gap_us)
                act_dur_us = max(0.0, (cur_active_end - cur_active_start) * 1_000_000.0)
                if act_dur_us > 0:
                    active_times.append(act_dur_us)
                cur_active_start = self.all_packets[i].timestamp
            cur_active_end = self.all_packets[i].timestamp

        if cur_active_end > cur_active_start:
            act_dur_us = (cur_active_end - cur_active_start) * 1_000_000.0
            if act_dur_us > 0:
                active_times.append(act_dur_us)

        active_mean = _safe_mean(active_times)
        active_std = _safe_std(active_times, active_mean)
        active_max = float(max(active_times)) if active_times else 0.0
        active_min = float(min(active_times)) if active_times else 0.0

        idle_mean = _safe_mean(idle_times)
        idle_std = _safe_std(idle_times, idle_mean)
        idle_max = float(max(idle_times)) if idle_times else 0.0
        idle_min = float(min(idle_times)) if idle_times else 0.0

        return {
            "Destination Port": float(self.bwd_port),
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": float(total_fwd_pkts),
            "Total Backward Packets": float(total_bwd_pkts),
            "Total Length of Fwd Packets": total_len_fwd,
            "Total Length of Bwd Packets": total_len_bwd,
            "Fwd Packet Length Max": fwd_len_max,
            "Fwd Packet Length Min": fwd_len_min,
            "Fwd Packet Length Mean": fwd_len_mean,
            "Fwd Packet Length Std": fwd_len_std,
            "Bwd Packet Length Max": bwd_len_max,
            "Bwd Packet Length Min": bwd_len_min,
            "Bwd Packet Length Mean": bwd_len_mean,
            "Bwd Packet Length Std": bwd_len_std,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_total,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": fwd_psh_flags,
            "Fwd URG Flags": fwd_urg_flags,
            "Fwd Header Length": fwd_header_len,
            "Bwd Header Length": bwd_header_len,
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Min Packet Length": min_pkt_len,
            "Max Packet Length": max_pkt_len,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "Packet Length Variance": pkt_len_var,
            "FIN Flag Count": fin_count,
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": urg_count,
            "CWE Flag Count": cwe_count,
            "ECE Flag Count": ece_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": avg_fwd_seg_size,
            "Avg Bwd Segment Size": avg_bwd_seg_size,
            "Fwd Header Length.1": fwd_header_len,  # Identical duplicate feature in CICIDS2017
            "Subflow Fwd Packets": subflow_fwd_pkts,
            "Subflow Fwd Bytes": subflow_fwd_bytes,
            "Subflow Bwd Packets": subflow_bwd_pkts,
            "Subflow Bwd Bytes": subflow_bwd_bytes,
            "Init_Win_bytes_forward": init_win_fwd,
            "Init_Win_bytes_backward": init_win_bwd,
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "min_seg_size_forward": min_seg_size_fwd,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
        }

    def get_metadata(self) -> Dict[str, Any]:
        duration_ms = max(0.0, (self.last_time - self.start_time) * 1000.0)
        return {
            "source_ip": self.fwd_ip,
            "destination_ip": self.bwd_ip,
            "source_port": self.fwd_port,
            "destination_port": self.bwd_port,
            "protocol": self.protocol,
            "start_time": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "last_time": datetime.fromtimestamp(self.last_time, tz=timezone.utc).isoformat(),
            "packet_start_time": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "packet_end_time": datetime.fromtimestamp(self.last_time, tz=timezone.utc).isoformat(),
            "packet_start_epoch": float(self.start_time),
            "packet_end_epoch": float(self.last_time),
            "capture_origin": self.capture_origin,
            "interface": self.interface,
            "close_reason": self.close_reason,
            "packet_count": len(self.all_packets),
            "total_bytes": sum(p.length for p in self.all_packets),
            "duration_ms": round(duration_ms, 2),
        }


class FlowAggregator:
    """
    Manages active bidirectional flows indexed by 5-tuple.
    Supports flow expiration by timeout, clean TCP teardown tracking,
    and suppression of late duplicate straggler packets.
    """

    def __init__(
        self,
        flow_timeout_seconds: float = 15.0,
        capture_origin: str = "npcap_live_nic",
        interface: str = "",
        max_active_flows: int = 10000,
        max_recently_closed: int = 5000,
    ):
        self.flow_timeout = flow_timeout_seconds
        self.capture_origin = capture_origin
        self.interface = interface
        self.max_active_flows = max_active_flows
        self.max_recently_closed = max_recently_closed
        # Map: flow_id -> BiFlow
        self.active_flows: Dict[str, BiFlow] = {}
        # Track recently closed flows to suppress trailing duplicate straggler packets
        self.recently_closed: Dict[str, float] = {}
        self.duplicates_prevented: int = 0

    @staticmethod
    def get_flow_id(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> Tuple[str, bool]:
        """
        Generates a canonical bidirectional flow ID and returns whether
        the packet is in the forward direction.
        Canonical ID sorts the endpoint tuples.
        """
        fwd_tuple = (src_ip, src_port)
        bwd_tuple = (dst_ip, dst_port)

        if fwd_tuple <= bwd_tuple:
            return f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}_{proto}", True
        else:
            return f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}_{proto}", False

    def ingest_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        proto: str,
        timestamp: float,
        length: int,
        payload_len: int,
        header_len: int,
        flags: int = 0,
        window_size: int = 0,
    ) -> Optional[BiFlow]:
        """
        Ingests a packet into the aggregator.
        Returns a completed BiFlow if the flow just reached closure (FIN handshake / RST), else None.
        Suppresses duplicate trailing straggler packets from recently closed connections.
        """
        canonical_id, is_canonical_fwd = self.get_flow_id(src_ip, src_port, dst_ip, dst_port, proto)

        # Expire old entries from recently closed suppression cache (5s window)
        cutoff = timestamp - 5.0
        if len(self.recently_closed) > self.max_recently_closed or any(v <= cutoff for v in self.recently_closed.values()):
            self.recently_closed = {k: v for k, v in self.recently_closed.items() if v > cutoff}

        # If this packet belongs to a flow that closed within the last 5 seconds,
        # absorb trailing ACKs/stragglers, but NEVER swallow a new connection SYN
        is_syn = bool(flags & 0x02)
        if canonical_id in self.recently_closed and not is_syn:
            if payload_len == 0 or (flags & 0x10):
                self.duplicates_prevented += 1
                return None

        if canonical_id not in self.active_flows:
            # Capacity guard: If active_flows exceeds maximum, evict oldest idle flow
            if len(self.active_flows) >= self.max_active_flows:
                oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].last_time)
                del self.active_flows[oldest_key]

            # First packet establishes the forward direction
            flow = BiFlow(
                fwd_ip=src_ip,
                fwd_port=src_port,
                bwd_ip=dst_ip,
                bwd_port=dst_port,
                protocol=proto,
                start_time=timestamp,
                capture_origin=self.capture_origin,
                interface=self.interface,
            )
            flow.add_packet(
                timestamp=timestamp,
                length=length,
                payload_len=payload_len,
                header_len=header_len,
                is_fwd=True,
                flags=flags,
                window_size=window_size,
            )
            if flow.is_closed:
                # Immediate single-packet closure (e.g. immediate RST)
                self.recently_closed[canonical_id] = timestamp
                return flow

            self.active_flows[canonical_id] = flow
            return None
        else:
            flow = self.active_flows[canonical_id]
            is_fwd = (src_ip == flow.fwd_ip and src_port == flow.fwd_port)
            flow.add_packet(
                timestamp=timestamp,
                length=length,
                payload_len=payload_len,
                header_len=header_len,
                is_fwd=is_fwd,
                flags=flags,
                window_size=window_size,
            )

            if flow.is_closed:
                # Flow reached complete closure (both FINs received or RST observed)
                del self.active_flows[canonical_id]
                self.recently_closed[canonical_id] = timestamp
                return flow

            return None

    def flush_expired(self, current_time: float) -> List[BiFlow]:
        """
        Flushes and returns flows that have been idle longer than the timeout.
        If a flow has already seen one FIN (half-closed), uses an expedited 5.0s teardown timeout.
        """
        expired: List[BiFlow] = []
        keys_to_remove: List[str] = []

        for key, flow in self.active_flows.items():
            timeout = 5.0 if (flow.fwd_fin or flow.bwd_fin) else self.flow_timeout
            if (current_time - flow.last_time) >= timeout:
                flow.close_reason = "tcp_half_close_timeout" if (flow.fwd_fin or flow.bwd_fin) else "idle_timeout"
                flow.is_closed = True
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.active_flows[key]
            self.recently_closed[key] = current_time

        return expired

    def flush_all(self) -> List[BiFlow]:
        """
        Flushes all remaining flows (used at end of PCAP file ingestion or session stop).
        """
        flows = list(self.active_flows.values())
        for f in flows:
            if not f.is_closed:
                f.close_reason = "manual_flush"
                f.is_closed = True
        self.active_flows.clear()
        return flows
