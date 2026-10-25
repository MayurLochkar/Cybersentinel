"""
Live Network Capture Adapter for CyberSentinel-X.

Provides authorized interface discovery and real-time packet sniffing using Scapy and Npcap.
Detects operating system capabilities (Npcap on Windows), resolves interface names safely,
guarantees clean lifecycle management (safe start/stop), and strictly separates genuine live
packet capture from explicit demo/simulated telemetry.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from scapy.all import IP, IPv6, TCP, UDP, ICMP, conf, get_if_list, sniff

from monitoring.flow_extractor import BiFlow, FlowAggregator

logger = logging.getLogger("cybersentinel.monitoring")


def is_pcap_available() -> bool:
    """
    Checks if a libpcap / Npcap provider is available for live packet sniffing.
    """
    try:
        return bool(conf.use_pcap)
    except Exception:
        return False


def resolve_scapy_interface(target: Optional[str] = None) -> Any:
    """
    Resolves an interface identifier (name, GUID, device path, IP, or description)
    to a Scapy NetworkInterface object or device identifier suitable for sniff().
    """
    if not target or target.strip() in ("", "Auto-Detect Default"):
        # Select best default: routable IP adapter if available, otherwise conf.iface
        for iface in conf.ifaces.values():
            ip_val = getattr(iface, "ip", "")
            name = getattr(iface, "name", "")
            if ip_val and not ip_val.startswith("169.254") and ip_val != "127.0.0.1" and "-0000" not in name:
                return iface
        return conf.iface

    target_clean = target.strip()

    # 1. Exact match in conf.ifaces by device key
    if target_clean in conf.ifaces:
        return conf.ifaces[target_clean]

    # 2. dev_from_name
    try:
        dev = conf.ifaces.dev_from_name(target_clean)
        if dev:
            return dev
    except Exception:
        pass

    # 3. Exact match on name, description, guid, ip, or pcap_name (case-insensitive)
    t_lower = target_clean.lower()
    for iface in conf.ifaces.values():
        name = getattr(iface, "name", "").lower()
        desc = getattr(iface, "description", "").lower()
        guid = getattr(iface, "guid", "").lower()
        ip = getattr(iface, "ip", "").lower()
        pcap_name = getattr(iface, "pcap_name", "").lower()
        if t_lower in (name, desc, guid, ip, pcap_name):
            return iface

    # 4. Partial substring match for clean adapter name (excluding NDIS filter drivers)
    for iface in conf.ifaces.values():
        name = getattr(iface, "name", "")
        desc = getattr(iface, "description", "")
        if "-0000" in name or "Filter Driver" in name:
            continue
        if t_lower in name.lower() or t_lower in desc.lower():
            return iface

    # 5. Fallback to target string directly
    return target_clean


def get_available_interfaces() -> List[Dict[str, Any]]:
    """
    Returns a clean list of physical and virtual network interfaces detected on the host,
    filtering out noisy NDIS lightweight filter drivers on Windows.
    """
    interfaces: List[Dict[str, Any]] = []
    seen_names = set()

    try:
        raw_list = list(conf.ifaces.values())
        for iface_obj in raw_list:
            name = str(getattr(iface_obj, "name", "")).strip() or str(iface_obj).strip()
            desc = str(getattr(iface_obj, "description", name) or name).strip()

            # Filter out internal Windows NDIS lightweight filter drivers
            if (
                "-0000" in name
                or "Filter Driver" in name
                or "Packet Scheduler" in name
                or "LightWeight Filter" in name
                or "VirtualBox NDIS" in name
            ):
                continue

            if not name or name in seen_names:
                continue
            seen_names.add(name)

            ip = getattr(iface_obj, "ip", "")
            mac = getattr(iface_obj, "mac", "")
            guid = getattr(iface_obj, "guid", name)

            is_loopback = (
                "loopback" in desc.lower()
                or "loopback" in name.lower()
                or ip == "127.0.0.1"
                or "Loopback" in str(iface_obj)
            )

            interfaces.append({
                "id": str(guid),
                "name": str(name),
                "description": str(desc),
                "ip": str(ip) if ip else "Not Assigned",
                "mac": str(mac) if mac else "",
                "is_loopback": is_loopback,
            })

        # Ensure loopback is always listed
        if not any(i["is_loopback"] for i in interfaces):
            interfaces.append({
                "id": "\\Device\\NPF_Loopback",
                "name": "Software Loopback Interface",
                "description": "Local Software Loopback",
                "ip": "127.0.0.1",
                "mac": "00:00:00:00:00:00",
                "is_loopback": True,
            })

        # Sort: adapters with valid routable IP first, then loopback, then APIPA/unassigned
        def iface_priority(item: Dict[str, Any]) -> Tuple[int, str]:
            ip_val = item.get("ip", "")
            has_real_ip = ip_val and ip_val != "Not Assigned" and not ip_val.startswith("169.254")
            if has_real_ip:
                prio = 0
            elif item.get("is_loopback"):
                prio = 1
            elif ip_val.startswith("169.254"):
                prio = 2
            else:
                prio = 3
            return (prio, item.get("name", ""))

        interfaces.sort(key=iface_priority)
    except Exception as exc:
        logger.warning(f"Error enumerating interfaces with Scapy: {exc}")
        try:
            for if_name in get_if_list():
                interfaces.append({
                    "id": str(if_name),
                    "name": str(if_name),
                    "description": str(if_name),
                    "ip": "Auto-detect",
                    "mac": "",
                    "is_loopback": False,
                })
        except Exception:
            pass

    return interfaces


class LiveCaptureSession:
    """
    Manages a live packet capture session on an authorized network interface.
    Supports genuine raw NIC sniffing via Npcap or an explicitly requested demo mode.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        flow_callback: Optional[Callable[[BiFlow], None]] = None,
        flow_timeout: float = 15.0,
        capture_mode: str = "real",
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flow_callback = flow_callback
        self.flow_timeout = flow_timeout
        self.capture_mode = capture_mode.lower()  # "real" or "demo"

        self.aggregator = FlowAggregator(flow_timeout_seconds=flow_timeout)
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._is_running = False
        self._error_message: Optional[str] = None

        self.packets_captured: int = 0
        self._capture_iface: Any = None
        self.resolved_interface_name: str = ""

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def error_message(self) -> Optional[str]:
        return self._error_message

    def _packet_handler(self, pkt: Any) -> None:
        if self._stop_event.is_set():
            return

        try:
            ts = float(getattr(pkt, "time", time.time()))

            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                return

            self.packets_captured += 1

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
                return

            total_hdr_len = ip_hdr_len + trans_hdr_len

            closed_flow = self.aggregator.ingest_packet(
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

            if closed_flow is not None and self.flow_callback:
                self.flow_callback(closed_flow)

        except Exception as exc:
            logger.debug(f"Packet handling error: {exc}")

    def _flush_loop(self) -> None:
        """Background worker that flushes timed-out idle flows."""
        while not self._stop_event.is_set():
            time.sleep(1.5)
            now = time.time()
            try:
                expired = self.aggregator.flush_expired(now)
                for flow in expired:
                    if self.flow_callback:
                        self.flow_callback(flow)
            except Exception as exc:
                logger.debug(f"Flush error: {exc}")

    def _sniff_worker(self) -> None:
        """Worker thread running Scapy sniff on physical/virtual NIC."""
        # Prevent self-monitoring telemetry feedback loop from local management API / UI
        management_filter = "not (port 8000 or port 3000)"
        if self.bpf_filter and self.bpf_filter.strip():
            user_f = self.bpf_filter.strip()
            if "port 8000" not in user_f and "port 3000" not in user_f:
                effective_filter = f"({user_f}) and ({management_filter})"
            else:
                effective_filter = user_f
        else:
            effective_filter = management_filter

        logger.info(
            f"Starting REAL LIVE NIC sniffer on interface '{self.resolved_interface_name}' "
            f"(filter: {effective_filter})."
        )
        try:
            sniff_kwargs: Dict[str, Any] = {
                "iface": self._capture_iface,
                "prn": self._packet_handler,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }
            if effective_filter:
                sniff_kwargs["filter"] = effective_filter

            sniff(**sniff_kwargs)
        except PermissionError:
            self._error_message = (
                "Permission denied: Packet capture requires Administrator privileges. "
                "Please run your terminal or IDE as Administrator to capture on this physical NIC."
            )
            logger.error(self._error_message)
        except Exception as exc:
            err_str = str(exc)
            if "pcap" in err_str.lower() or "winpcap" in err_str.lower() or "npcap" in err_str.lower():
                self._error_message = (
                    "Npcap capture error: Failed to access capture device. "
                    "Ensure Npcap is installed with WinPcap API-compatible mode enabled."
                )
            else:
                self._error_message = f"Live capture halted: {exc}"
            logger.error(self._error_message)
        finally:
            self._is_running = False

    def _live_telemetry_worker(self) -> None:
        """
        Explicit DEMO / SIMULATED telemetry engine.
        Generates authorized simulated network packets in memory for test and verification.
        Never to be confused or misrepresented as raw NIC capture.
        """
        import random
        from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw

        logger.info("Started DEMO / SIMULATED network traffic generator (Explicit Demo Mode).")
        pkt_seq = 1000

        while not self._stop_event.is_set():
            time.sleep(random.uniform(1.2, 2.2))
            if self._stop_event.is_set():
                break

            now = time.time()
            scenario = random.choices(["http", "dns", "probe", "api"], weights=[0.45, 0.30, 0.15, 0.10])[0]

            try:
                if scenario == "http":
                    sport = random.randint(49152, 65535)
                    p1 = IP(src="192.168.29.93", dst="10.0.0.15") / TCP(sport=sport, dport=80, flags="S", seq=pkt_seq, window=64240)
                    p1.time = now
                    self._packet_handler(p1)
                    p2 = IP(src="10.0.0.15", dst="192.168.29.93") / TCP(sport=80, dport=sport, flags="SA", seq=pkt_seq + 1000, ack=pkt_seq + 1, window=65535)
                    p2.time = now + 0.015
                    self._packet_handler(p2)
                    req = "GET /api/v1/telemetry HTTP/1.1\r\nHost: local.soc\r\n\r\n"
                    p3 = IP(src="192.168.29.93", dst="10.0.0.15") / TCP(sport=sport, dport=80, flags="PA", seq=pkt_seq + 1, ack=pkt_seq + 1001) / Raw(load=req)
                    p3.time = now + 0.030
                    self._packet_handler(p3)
                    p4 = IP(src="192.168.29.93", dst="10.0.0.15") / TCP(sport=sport, dport=80, flags="FA", seq=pkt_seq + 1 + len(req), ack=pkt_seq + 1001)
                    p4.time = now + 0.050
                    self._packet_handler(p4)

                elif scenario == "dns":
                    sport = random.randint(49152, 65535)
                    dns_req = IP(src="192.168.29.93", dst="1.1.1.1") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname="auth.sentinel.corp"))
                    dns_req.time = now
                    self._packet_handler(dns_req)
                    dns_res = IP(src="1.1.1.1", dst="192.168.29.93") / UDP(sport=53, dport=sport) / DNS(qr=1, rd=1, ra=1, qd=DNSQR(qname="auth.sentinel.corp"))
                    dns_res.time = now + 0.020
                    self._packet_handler(dns_res)

                elif scenario == "probe":
                    sport = random.randint(40000, 50000)
                    probe1 = IP(src="185.190.22.40", dst="10.0.0.8") / TCP(sport=sport, dport=80, flags="S", seq=pkt_seq, window=253)
                    probe1.time = now
                    self._packet_handler(probe1)
                    probe2 = IP(src="10.0.0.8", dst="185.190.22.40") / TCP(sport=80, dport=sport, flags="R", seq=0, ack=pkt_seq + 1, window=243)
                    probe2.time = now + 0.000070
                    self._packet_handler(probe2)

                else:
                    sport = random.randint(49152, 65535)
                    p_api = IP(src="192.168.29.93", dst="10.0.0.21") / TCP(sport=sport, dport=443, flags="PA", seq=pkt_seq, window=32768) / Raw(load=b"\x17\x03\x03\x00\x28" + b"A" * 40)
                    p_api.time = now
                    self._packet_handler(p_api)
                    p_fin = IP(src="192.168.29.93", dst="10.0.0.21") / TCP(sport=sport, dport=443, flags="FA", seq=pkt_seq + 45, window=32768)
                    p_fin.time = now + 0.030
                    self._packet_handler(p_fin)

                pkt_seq += 100
            except Exception as exc:
                logger.debug(f"Demo loop packet error: {exc}")

    def start(self) -> None:
        """Starts packet capture in the background."""
        if self._is_running:
            return

        self._stop_event.clear()
        self._error_message = None
        self.packets_captured = 0

        if self.capture_mode == "real":
            if not is_pcap_available():
                raise RuntimeError(
                    "Npcap capture provider is not available or inactive. "
                    "Real live packet capture requires Npcap (https://npcap.com) with "
                    "WinPcap API-compatible mode enabled. Real capture will not silently simulate traffic."
                )

            resolved = resolve_scapy_interface(self.interface)
            self._capture_iface = resolved
            self.resolved_interface_name = str(getattr(resolved, "name", resolved))
            self.aggregator.capture_origin = "npcap_live_nic"
            self.aggregator.interface = self.resolved_interface_name
            target_worker = self._sniff_worker
        elif self.capture_mode == "demo":
            self.resolved_interface_name = "SIMULATED-DEMO-STREAM"
            self.aggregator.capture_origin = "demo_simulation"
            self.aggregator.interface = "SIMULATED-DEMO-STREAM"
            target_worker = self._live_telemetry_worker
        else:
            raise ValueError(f"Unknown capture mode: '{self.capture_mode}'. Must be 'real' or 'demo'.")

        self._is_running = True

        self._capture_thread = threading.Thread(
            target=target_worker,
            name="CyberSentinel-LiveSniffer",
            daemon=True,
        )
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="CyberSentinel-FlowFlusher",
            daemon=True,
        )

        self._capture_thread.start()
        self._flush_thread.start()

        # If running in real NIC mode, wait briefly to ensure initialization succeeded
        if self.capture_mode == "real":
            time.sleep(0.08)
            if self._error_message or not self._is_running:
                self.stop()
                raise RuntimeError(
                    self._error_message or "Failed to initialize live packet sniffing on selected adapter."
                )

    def stop(self) -> None:
        """Stops packet capture safely and flushes remaining active flows."""
        self._stop_event.set()
        self._is_running = False

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.5)
        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=1.5)

        # Flush remaining flows through the callback
        try:
            remaining = self.aggregator.flush_all()
            for flow in remaining:
                if self.flow_callback:
                    self.flow_callback(flow)
        except Exception as exc:
            logger.debug(f"Error during final flow flush: {exc}")
