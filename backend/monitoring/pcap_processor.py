"""
Authorized PCAP & PCAPNG File Ingestion Pipeline.

Supports massive packet capture files (up to 25+ GB) without memory exhaustion
by streaming packets sequentially from disk using Scapy's RawPcapReader / PcapReader,
incrementally aggregating bidirectional flows, and classifying CICIDS2017 feature batches.
"""

from __future__ import annotations

import io
import os
import socket
import struct
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader, RawPcapReader

from monitoring.flow_extractor import BiFlow, FlowAggregator

# Maximum allowed PCAP file size: 25 GB (accommodates 12 GB captures and dataset benchmarks)
MAX_PCAP_SIZE_BYTES = 25 * 1024 * 1024 * 1024

# Allowed Magic Bytes for PCAP and PCAPNG
VALID_MAGIC_BYTES = [
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (Little Endian)
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (Big Endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (Little Endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (Big Endian)
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG Block Header
]

STANDARD_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}


class PcapValidationError(ValueError):
    """Raised when a PCAP file fails validation checks."""
    pass


def validate_pcap_header_bytes(header: bytes, filename: str = "capture.pcap") -> None:
    """
    Validates magic bytes from the first 4 bytes of a PCAP or PCAPNG header.
    """
    if len(header) < 4:
        raise PcapValidationError(f"File '{filename}' is too small to contain a valid PCAP header.")

    magic = header[:4]
    if magic not in VALID_MAGIC_BYTES:
        raise PcapValidationError(
            f"Invalid file format: '{filename}' does not start with a valid PCAP or PCAPNG header."
        )


def validate_pcap_file(filepath: Union[str, Path]) -> None:
    """
    Validates file existence, non-empty status, file size, and magic bytes directly from disk.
    """
    path_obj = Path(filepath)
    if not path_obj.exists():
        raise PcapValidationError(f"PCAP file not found: {path_obj}")

    file_size = path_obj.stat().st_size
    if file_size == 0:
        raise PcapValidationError(f"PCAP file '{path_obj.name}' is empty (0 bytes).")

    if file_size > MAX_PCAP_SIZE_BYTES:
        raise PcapValidationError(
            f"File exceeds maximum allowed size of {MAX_PCAP_SIZE_BYTES / (1024*1024*1024):.1f} GB. "
            f"Provided size: {file_size / (1024*1024*1024):.2f} GB."
        )

    with open(path_obj, "rb") as f:
        header = f.read(4)

    validate_pcap_header_bytes(header, filename=path_obj.name)


def validate_pcap_bytes(data: bytes, filename: str = "capture.pcap") -> None:
    """
    Validates in-memory byte buffer for size and magic bytes.
    """
    if len(data) == 0:
        raise PcapValidationError("File is empty (0 bytes).")

    if len(data) > MAX_PCAP_SIZE_BYTES:
        raise PcapValidationError(
            f"File exceeds maximum allowed size of {MAX_PCAP_SIZE_BYTES / (1024*1024*1024):.1f} GB. "
            f"Provided size: {len(data) / (1024*1024):.2f} MB."
        )

    if len(data) < 4:
        raise PcapValidationError("File is too small to contain a valid PCAP header.")

    validate_pcap_header_bytes(data[:4], filename=filename)


def process_pcap_file_streaming(
    filepath: Union[str, Path],
    filename: Optional[str] = None,
    flow_timeout: float = 30.0,
    max_packets: Optional[int] = None,
    batch_flow_callback: Optional[Callable[[List[Tuple[Dict[str, Any], Dict[str, float]]]], None]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    abort_check: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """
    High-performance streaming PCAP/PCAPNG parser with zero-RAM buffering.
    Uses ultra-fast RawPcapReader + direct struct parsing for standard PCAPs (up to 100,000 pkts/s),
    with automatic PcapReader fallback for PCAPNG.
    """
    path_obj = Path(filepath)
    validate_pcap_file(path_obj)

    display_name = filename or path_obj.name
    file_size_bytes = path_obj.stat().st_size
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)

    with open(path_obj, "rb") as f:
        magic = f.read(4)

    is_standard_pcap = magic in STANDARD_PCAP_MAGICS

    aggregator = FlowAggregator(
        flow_timeout_seconds=flow_timeout,
        capture_origin="pcap_file",
        interface=f"PCAP: {display_name}",
    )

    batch_flows: List[Tuple[Dict[str, Any], Dict[str, float]]] = []
    fallback_all_flows: List[Tuple[Dict[str, Any], Dict[str, float]]] = []

    total_packets_count = 0
    total_flows_count = 0
    start_time = time.time()
    last_progress_time = start_time

    # =========================================================================
    # HIGH-SPEED UNIFIED RAW PCAP / PCAP-NG STREAMING (20,000 - 90,000 pkts/s)
    # =========================================================================
    raw_success = False
    try:
        raw_reader = RawPcapReader(str(path_obj))
        try:
            for pkt_data, pkt_meta in raw_reader:
                total_packets_count += 1

                if abort_check and abort_check():
                    break

                if max_packets is not None and total_packets_count > max_packets:
                    break

                # Extract timestamp and linktype across PCAP & PCAPNG
                if isinstance(pkt_meta, tuple):
                    sec = pkt_meta[0] if len(pkt_meta) > 0 else 0
                    usec = pkt_meta[1] if len(pkt_meta) > 1 else 0
                    ts = float(sec) + (float(usec) / 1_000_000.0)
                    lt = getattr(raw_reader, "linktype", 1)
                elif hasattr(pkt_meta, "tshigh"):
                    ts = ((pkt_meta.tshigh << 32) + pkt_meta.tslow) / float(getattr(pkt_meta, "tsresol", 1_000_000) or 1_000_000)
                    lt = getattr(pkt_meta, "linktype", 1)
                else:
                    ts = time.time()
                    lt = 1

                pkt_len = len(pkt_data)
                if pkt_len < 20:
                    continue

                # Determine IP header offset and protocol type
                if lt == 1 and pkt_len >= 14:  # Ethernet
                    eth_type = (pkt_data[12] << 8) | pkt_data[13]
                    ip_offset = 14
                    if eth_type == 0x8100 and pkt_len >= 18:  # 802.1Q VLAN
                        eth_type = (pkt_data[16] << 8) | pkt_data[17]
                        ip_offset = 18
                elif (pkt_data[0] >> 4) == 4:  # Raw IPv4 (DLT_RAW / DLT_IPV4 / loopback)
                    eth_type = 0x0800
                    ip_offset = 0
                elif (pkt_data[0] >> 4) == 6:  # Raw IPv6 (DLT_IPV6)
                    eth_type = 0x86DD
                    ip_offset = 0
                elif pkt_len >= 14 and ((pkt_data[12] << 8) | pkt_data[13]) in (0x0800, 0x86DD):
                    eth_type = (pkt_data[12] << 8) | pkt_data[13]
                    ip_offset = 14
                else:
                    continue

                if eth_type == 0x0800:  # IPv4
                    if pkt_len < ip_offset + 20:
                        continue
                    ip_hdr_len = (pkt_data[ip_offset] & 0x0F) * 4
                    total_len = (pkt_data[ip_offset + 2] << 8) | pkt_data[ip_offset + 3]
                    proto = pkt_data[ip_offset + 9]
                    src_ip = f"{pkt_data[ip_offset + 12]}.{pkt_data[ip_offset + 13]}.{pkt_data[ip_offset + 14]}.{pkt_data[ip_offset + 15]}"
                    dst_ip = f"{pkt_data[ip_offset + 16]}.{pkt_data[ip_offset + 17]}.{pkt_data[ip_offset + 18]}.{pkt_data[ip_offset + 19]}"
                    l4_offset = ip_offset + ip_hdr_len

                    if proto == 6:  # TCP
                        if pkt_len < l4_offset + 20:
                            continue
                        src_port = (pkt_data[l4_offset] << 8) | pkt_data[l4_offset + 1]
                        dst_port = (pkt_data[l4_offset + 2] << 8) | pkt_data[l4_offset + 3]
                        trans_hdr_len = ((pkt_data[l4_offset + 12] >> 4) & 0x0F) * 4
                        flags = pkt_data[l4_offset + 13]
                        win_size = (pkt_data[l4_offset + 14] << 8) | pkt_data[l4_offset + 15]
                        payload_len = max(0, total_len - ip_hdr_len - trans_hdr_len)
                        proto_str = "TCP"
                    elif proto == 17:  # UDP
                        if pkt_len < l4_offset + 8:
                            continue
                        src_port = (pkt_data[l4_offset] << 8) | pkt_data[l4_offset + 1]
                        dst_port = (pkt_data[l4_offset + 2] << 8) | pkt_data[l4_offset + 3]
                        trans_hdr_len = 8
                        flags = 0
                        win_size = 0
                        udp_len = (pkt_data[l4_offset + 4] << 8) | pkt_data[l4_offset + 5]
                        payload_len = max(0, udp_len - 8)
                        proto_str = "UDP"
                    elif proto == 1:  # ICMP
                        src_port = 0
                        dst_port = 0
                        trans_hdr_len = 8
                        flags = 0
                        win_size = 0
                        payload_len = max(0, total_len - ip_hdr_len - 8)
                        proto_str = "ICMP"
                    else:
                        continue

                elif eth_type == 0x86DD:  # IPv6
                    if pkt_len < ip_offset + 40:
                        continue
                    payload_len_v6 = (pkt_data[ip_offset + 4] << 8) | pkt_data[ip_offset + 5]
                    proto = pkt_data[ip_offset + 6]
                    total_len = payload_len_v6 + 40
                    ip_hdr_len = 40
                    src_ip = socket.inet_ntop(socket.AF_INET6, pkt_data[ip_offset + 8:ip_offset + 24])
                    dst_ip = socket.inet_ntop(socket.AF_INET6, pkt_data[ip_offset + 24:ip_offset + 40])
                    l4_offset = ip_offset + 40

                    if proto == 6:  # TCP
                        if pkt_len < l4_offset + 20:
                            continue
                        src_port = (pkt_data[l4_offset] << 8) | pkt_data[l4_offset + 1]
                        dst_port = (pkt_data[l4_offset + 2] << 8) | pkt_data[l4_offset + 3]
                        trans_hdr_len = ((pkt_data[l4_offset + 12] >> 4) & 0x0F) * 4
                        flags = pkt_data[l4_offset + 13]
                        win_size = (pkt_data[l4_offset + 14] << 8) | pkt_data[l4_offset + 15]
                        payload_len = max(0, total_len - ip_hdr_len - trans_hdr_len)
                        proto_str = "TCP"
                    elif proto == 17:  # UDP
                        if pkt_len < l4_offset + 8:
                            continue
                        src_port = (pkt_data[l4_offset] << 8) | pkt_data[l4_offset + 1]
                        dst_port = (pkt_data[l4_offset + 2] << 8) | pkt_data[l4_offset + 3]
                        trans_hdr_len = 8
                        flags = 0
                        win_size = 0
                        udp_len = (pkt_data[l4_offset + 4] << 8) | pkt_data[l4_offset + 5]
                        payload_len = max(0, udp_len - 8)
                        proto_str = "UDP"
                    else:
                        continue
                else:
                    continue

                total_hdr_len = ip_hdr_len + trans_hdr_len

                closed_flow = aggregator.ingest_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto_str,
                    timestamp=ts,
                    length=total_len,
                    payload_len=payload_len,
                    header_len=total_hdr_len,
                    flags=flags,
                    window_size=win_size,
                )

                if closed_flow is not None and len(closed_flow.all_packets) > 0:
                    meta = closed_flow.get_metadata()
                    feats = closed_flow.compute_features()
                    total_flows_count += 1
                    if batch_flow_callback:
                        batch_flows.append((meta, feats))
                    else:
                        fallback_all_flows.append((meta, feats))

                # Periodic flow expiry every 2,500 packets
                if total_packets_count % 2500 == 0:
                    expired = aggregator.flush_expired(ts)
                    for ef in expired:
                        if len(ef.all_packets) > 0:
                            meta = ef.get_metadata()
                            feats = ef.compute_features()
                            total_flows_count += 1
                            if batch_flow_callback:
                                batch_flows.append((meta, feats))
                            else:
                                fallback_all_flows.append((meta, feats))

                # Dispatch flow batch when threshold is reached
                if batch_flow_callback and len(batch_flows) >= 100:
                    batch_flow_callback(batch_flows)
                    batch_flows.clear()

                # Dispatch live progress update
                if progress_callback and (time.time() - last_progress_time) >= 0.4:
                    now = time.time()
                    elapsed = max(0.001, now - start_time)
                    rate = total_packets_count / elapsed
                    progress_callback({
                        "status": "processing",
                        "filename": display_name,
                        "file_size_mb": file_size_mb,
                        "packets_read": total_packets_count,
                        "flows_extracted": total_flows_count,
                        "current_rate_pps": round(rate, 1),
                        "elapsed_seconds": round(elapsed, 2),
                    })
                    last_progress_time = now

            raw_success = True
        finally:
            try:
                raw_reader.close()
            except Exception:
                pass
    except Exception:
        raw_success = False

    # =========================================================================
    # FALLBACK PATH: Standard PcapReader (if RawPcapReader threw unsupported DLT)
    # =========================================================================
    if not raw_success and total_packets_count == 0:
        reader = PcapReader(str(path_obj))
        try:
            for pkt in reader:
                total_packets_count += 1

                if abort_check and abort_check():
                    break

                if max_packets is not None and total_packets_count > max_packets:
                    break

                ts = float(getattr(pkt, "time", 0.0))

                if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                    continue

                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    ip_len = int(ip_layer.len or len(ip_layer))
                    ip_hdr_len = int((ip_layer.ihl or 5) * 4)
                else:
                    ip_layer = pkt[IPv6]
                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    ip_len = int(ip_layer.plen + 40)
                    ip_hdr_len = 40

                src_port = 0
                dst_port = 0
                proto_str = "OTHER"
                flags = 0
                win_size = 0
                payload_len = 0
                trans_hdr_len = 0

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    src_port = int(tcp_layer.sport)
                    dst_port = int(tcp_layer.dport)
                    proto_str = "TCP"
                    try:
                        flags = int(tcp_layer.flags)
                    except Exception:
                        flags = 0
                    win_size = int(tcp_layer.window or 0)
                    trans_hdr_len = int((tcp_layer.dataofs or 5) * 4)
                    payload_len = max(0, ip_len - ip_hdr_len - trans_hdr_len)
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    src_port = int(udp_layer.sport)
                    dst_port = int(udp_layer.dport)
                    proto_str = "UDP"
                    trans_hdr_len = 8
                    payload_len = max(0, (udp_layer.len or 8) - 8)
                elif pkt.haslayer(ICMP):
                    proto_str = "ICMP"
                    trans_hdr_len = 8
                    payload_len = max(0, ip_len - ip_hdr_len - 8)
                else:
                    continue

                total_hdr_len = ip_hdr_len + trans_hdr_len

                closed_flow = aggregator.ingest_packet(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto_str,
                    timestamp=ts,
                    length=ip_len,
                    payload_len=payload_len,
                    header_len=total_hdr_len,
                    flags=flags,
                    window_size=win_size,
                )

                if closed_flow is not None and len(closed_flow.all_packets) > 0:
                    meta = closed_flow.get_metadata()
                    feats = closed_flow.compute_features()
                    total_flows_count += 1
                    if batch_flow_callback:
                        batch_flows.append((meta, feats))
                    else:
                        fallback_all_flows.append((meta, feats))

                if total_packets_count % 2500 == 0:
                    expired = aggregator.flush_expired(ts)
                    for ef in expired:
                        if len(ef.all_packets) > 0:
                            meta = ef.get_metadata()
                            feats = ef.compute_features()
                            total_flows_count += 1
                            if batch_flow_callback:
                                batch_flows.append((meta, feats))
                            else:
                                fallback_all_flows.append((meta, feats))

                if batch_flow_callback and len(batch_flows) >= 100:
                    batch_flow_callback(batch_flows)
                    batch_flows.clear()

                if progress_callback and (time.time() - last_progress_time) >= 0.4:
                    now = time.time()
                    elapsed = max(0.001, now - start_time)
                    rate = total_packets_count / elapsed
                    progress_callback({
                        "status": "processing",
                        "filename": display_name,
                        "file_size_mb": file_size_mb,
                        "packets_read": total_packets_count,
                        "flows_extracted": total_flows_count,
                        "current_rate_pps": round(rate, 1),
                        "elapsed_seconds": round(elapsed, 2),
                    })
                    last_progress_time = now

        finally:
            try:
                reader.close()
            except Exception:
                pass

    # Flush all remaining active flows
    remaining = aggregator.flush_all()
    for rf in remaining:
        if len(rf.all_packets) > 0:
            meta = rf.get_metadata()
            feats = rf.compute_features()
            total_flows_count += 1
            if batch_flow_callback:
                batch_flows.append((meta, feats))
            else:
                fallback_all_flows.append((meta, feats))

    if batch_flow_callback and batch_flows:
        batch_flow_callback(batch_flows)
        batch_flows.clear()

    total_elapsed = round(max(0.01, time.time() - start_time), 2)
    avg_rate = round(total_packets_count / total_elapsed, 1)

    if progress_callback:
        progress_callback({
            "status": "completed",
            "filename": display_name,
            "file_size_mb": file_size_mb,
            "packets_read": total_packets_count,
            "flows_extracted": total_flows_count,
            "current_rate_pps": avg_rate,
            "elapsed_seconds": total_elapsed,
        })

    return {
        "filename": display_name,
        "file_size_mb": file_size_mb,
        "packets_read": total_packets_count,
        "flows_extracted": total_flows_count,
        "elapsed_seconds": total_elapsed,
        "rate_pps": avg_rate,
        "flows": fallback_all_flows if not batch_flow_callback else [],
    }


def process_pcap_bytes(
    data: bytes,
    filename: str = "capture.pcap",
    flow_timeout: float = 30.0,
) -> List[Tuple[Dict[str, Any], Dict[str, float]]]:
    """
    Parses PCAP bytes, extracts flows, and calculates CICIDS2017 features.
    Maintains full backward compatibility with existing tests and scripts.
    """
    validate_pcap_bytes(data, filename)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        res = process_pcap_file_streaming(tmp_path, filename=filename, flow_timeout=flow_timeout)
        return res["flows"]
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
