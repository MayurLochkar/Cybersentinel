"""
Sample PCAP Generator for CyberSentinel-X Verification.

Generates small, authorized synthetic packet captures (loopback/lab traffic)
containing both BENIGN web/DNS traffic flows and suspicious scanning/flood flows
to verify end-to-end feature extraction, ML inference, and alert triggering.
"""

from __future__ import annotations

import io
import time
from typing import List

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def generate_sample_pcap_bytes() -> bytes:
    """
    Creates an authorized PCAP byte stream with:
    1. A BENIGN HTTP GET flow (handshake, request, 200 OK, teardown).
    2. A BENIGN DNS Query/Response flow.
    3. An ATTACK-like rapid Port Probe flow (SYN packets without ACK).
    """
    packets = []
    base_time = time.time() - 60.0

    # Flow 1: Normal HTTP conversation (192.168.1.105:54321 -> 10.0.0.15:80)
    # SYN
    p1 = IP(src="192.168.1.105", dst="10.0.0.15") / TCP(sport=54321, dport=80, flags="S", seq=1000, window=64240)
    p1.time = base_time + 0.000
    # SYN-ACK
    p2 = IP(src="10.0.0.15", dst="192.168.1.105") / TCP(sport=80, dport=54321, flags="SA", seq=5000, ack=1001, window=65535)
    p2.time = base_time + 0.015
    # ACK
    p3 = IP(src="192.168.1.105", dst="10.0.0.15") / TCP(sport=54321, dport=80, flags="A", seq=1001, ack=5001, window=64240)
    p3.time = base_time + 0.020
    # HTTP GET Request
    http_req = "GET /index.html HTTP/1.1\r\nHost: intranet.corp\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    p4 = IP(src="192.168.1.105", dst="10.0.0.15") / TCP(sport=54321, dport=80, flags="PA", seq=1001, ack=5001) / Raw(load=http_req)
    p4.time = base_time + 0.050
    # HTTP 200 Response
    http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>Authorized SOC Service</body></html>"
    p5 = IP(src="10.0.0.15", dst="192.168.1.105") / TCP(sport=80, dport=54321, flags="PA", seq=5001, ack=1001 + len(http_req)) / Raw(load=http_resp)
    p5.time = base_time + 0.080
    # Client ACK
    p6 = IP(src="192.168.1.105", dst="10.0.0.15") / TCP(sport=54321, dport=80, flags="A", seq=1001 + len(http_req), ack=5001 + len(http_resp))
    p6.time = base_time + 0.090
    # FIN-ACK
    p7 = IP(src="192.168.1.105", dst="10.0.0.15") / TCP(sport=54321, dport=80, flags="FA", seq=1001 + len(http_req), ack=5001 + len(http_resp))
    p7.time = base_time + 0.120
    # Server FIN-ACK
    p8 = IP(src="10.0.0.15", dst="192.168.1.105") / TCP(sport=80, dport=54321, flags="FA", seq=5001 + len(http_resp), ack=1002 + len(http_req))
    p8.time = base_time + 0.130

    packets.extend([p1, p2, p3, p4, p5, p6, p7, p8])

    # Flow 2: Normal DNS Query & Response (192.168.1.105:61234 -> 1.1.1.1:53 UDP)
    dns_query = IP(src="192.168.1.105", dst="1.1.1.1") / UDP(sport=61234, dport=53) / DNS(rd=1, qd=DNSQR(qname="api.internal.corp"))
    dns_query.time = base_time + 1.000
    dns_resp = IP(src="1.1.1.1", dst="192.168.1.105") / UDP(sport=53, dport=61234) / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="api.internal.corp"))
    dns_resp.time = base_time + 1.025

    packets.extend([dns_query, dns_resp])

    # Flow 3: Rapid SYN Port Sweep / Probe (185.190.22.40 -> 10.0.0.21:22 SSH brute-probe)
    for i in range(12):
        probe = IP(src="185.190.22.40", dst="10.0.0.21") / TCP(sport=40000 + i, dport=22, flags="S", seq=20000 + i, window=1024)
        probe.time = base_time + 2.000 + (i * 0.002)  # High packet rate
        packets.append(probe)

    # Flow 4: Rapid PortScan SYN/RST probe (185.190.22.40:55000 -> 10.0.0.8:80)
    p_scan1 = IP(src="185.190.22.40", dst="10.0.0.8") / TCP(sport=55000, dport=80, flags="S", seq=30000, window=253)
    p_scan1.time = base_time + 3.000000
    p_scan2 = IP(src="10.0.0.8", dst="185.190.22.40") / TCP(sport=80, dport=55000, flags="R", seq=0, ack=30001, window=243)
    p_scan2.time = base_time + 3.000070  # 70us duration matches CICIDS2017 PortScan
    packets.extend([p_scan1, p_scan2])

    import os
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        wrpcap(tmp_path, packets)
        with open(tmp_path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
