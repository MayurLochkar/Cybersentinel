"""
CyberSentinel-X - Defensible Protocol Validation Engine.
=========================================================
Validates protocol compliance and distinguishes:
1. VALID_BENIGN: Legitimate protocol exchanges (e.g. standard RFC 2131 DHCP client discovery,
   local multicast discovery, standard DNS query). When ML produces borderline false positives
   due to out-of-distribution training variance, this safely suppresses or downgrades the alert.
2. SUSPICIOUS_ANOMALY: Protocol behavior diverging from RFC norms or exhibiting suspicious rates/sizes,
   preserved for analyst investigation.
3. CONFIRMED_ATTACK: Unambiguous protocol exploitation (e.g. DHCP Starvation / Exhaustion flood,
   volumetric UDP reflection, SYN flood).
4. UNVERIFIED: General traffic requiring downstream ML and flow evidence evaluation.

Never whitelists traffic on port numbers alone.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class ProtocolValidationResult:
    verdict: str  # "VALID_BENIGN" | "SUSPICIOUS_ANOMALY" | "CONFIRMED_ATTACK" | "UNVERIFIED"
    protocol_name: str
    is_protocol_compliant: bool
    should_suppress_alert: bool
    suggested_attack_type: Optional[str]
    suggested_severity: Optional[str]
    explanation: str
    evidence_telemetry: Dict[str, Any]


def validate_protocol_flow(
    metadata: Dict[str, Any],
    features: Dict[str, float],
    ml_prediction: Dict[str, Any],
) -> ProtocolValidationResult:
    """
    Validates flow telemetry against strict RFC protocol behavior.
    Cross-checks with ML prediction to eliminate out-of-distribution false alarms
    while preserving actual attacks for triage.
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

    ml_class = str(ml_prediction.get("prediction", "BENIGN")).upper()
    ml_conf = float(ml_prediction.get("confidence_percent", 0.0))

    telemetry = {
        "protocol": proto,
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "packet_count": pkts,
        "total_bytes": total_bytes,
        "duration_ms": round(duration_ms, 2),
        "packet_rate_pps": round(packet_rate, 2),
        "average_packet_size": round(avg_pkt_size, 2),
        "ml_raw_prediction": ml_class,
        "ml_raw_confidence": ml_conf,
    }

    # =========================================================================
    # 1. DHCP Protocol Validation (RFC 2131 / RFC 2132)
    # Standard: UDP Client (port 68) <-> Server (port 67), or broadcast discovery
    # =========================================================================
    is_dhcp = (
        proto == "UDP"
        and (
            (src_port in (67, 68) and dst_port in (67, 68))
            or (dst_ip in ("255.255.255.255", "0.0.0.0") and dst_port in (67, 68))
        )
    )

    if is_dhcp:
        # A standard DHCP 4-way DORA (Discover, Offer, Request, Ack) or 2-way lease renewal
        # consists of 1 to 8 packets, message sizes between 240 and 600 bytes.
        is_normal_packet_count = pkts <= 8
        is_normal_packet_size = 150 <= avg_pkt_size <= 700

        # Detect DHCP Starvation / Flooding Attack: requires substantial volume
        if (pkts > 20 and packet_rate > 20.0) or pkts >= 35 or total_bytes > 30000:
            return ProtocolValidationResult(
                verdict="CONFIRMED_ATTACK",
                protocol_name="DHCP (RFC 2131)",
                is_protocol_compliant=False,
                should_suppress_alert=False,
                suggested_attack_type="DHCP Starvation / Flooding Attack",
                suggested_severity="HIGH" if packet_rate < 100 else "CRITICAL",
                explanation=(
                    f"DHCP Protocol Violation: Detected high-volume packet burst "
                    f"({pkts} packets at {packet_rate:.1f} pkts/sec, {total_bytes} bytes). "
                    f"Exceeds RFC 2131 lease negotiation bounds; matches DHCP Starvation / Exhaustion profile."
                ),
                evidence_telemetry=telemetry,
            )

        # Detect Malformed / Oversized DHCP Tunneling Anomaly
        if avg_pkt_size > 1100:
            return ProtocolValidationResult(
                verdict="SUSPICIOUS_ANOMALY",
                protocol_name="DHCP (RFC 2131)",
                is_protocol_compliant=False,
                should_suppress_alert=False,
                suggested_attack_type="Suspicious DHCP Protocol Anomaly",
                suggested_severity="MEDIUM",
                explanation=(
                    f"DHCP Telemetry Anomaly: Packet size ({avg_pkt_size:.1f} bytes) "
                    f"substantially exceeds standard BOOTP/DHCP message limits (< 600 bytes). "
                    f"Preserved for inspection for potential DNS/DHCP tunneling."
                ),
                evidence_telemetry=telemetry,
            )

        # Standard Legitimate DHCP Exchange
        if is_normal_packet_count and (is_normal_packet_size or avg_pkt_size <= 800):
            return ProtocolValidationResult(
                verdict="VALID_BENIGN",
                protocol_name="DHCP (RFC 2131)",
                is_protocol_compliant=True,
                should_suppress_alert=True,
                suggested_attack_type=None,
                suggested_severity="LOW",
                explanation=(
                    f"RFC 2131 DHCP Validation: Valid low-rate client lease exchange "
                    f"({pkts} packets, {total_bytes} bytes over {duration_ms:.1f}ms). "
                    f"Model prediction {ml_class} ({ml_conf:.1f}% confidence on port 67) "
                    f"identified as out-of-distribution training variance and safely suppressed."
                ),
                evidence_telemetry=telemetry,
            )

        # Borderline DHCP Anomaly (between 9 and 20 packets)
        return ProtocolValidationResult(
            verdict="SUSPICIOUS_ANOMALY",
            protocol_name="DHCP (RFC 2131)",
            is_protocol_compliant=False,
            should_suppress_alert=False,
            suggested_attack_type="Suspicious DHCP Protocol Anomaly",
            suggested_severity="LOW",
            explanation=(
                f"DHCP Operational Anomaly: Flow exchanged {pkts} packets (expected <= 8). "
                f"Flagged with LOW severity for lease-cycling investigation."
            ),
            evidence_telemetry=telemetry,
        )

    # =========================================================================
    # 2. Local Link Discovery (mDNS 5353, LLMNR 5355, SSDP 1900)
    # =========================================================================
    is_local_discovery = proto == "UDP" and (
        dst_port in (5353, 5355, 1900)
        or dst_ip.startswith("224.0.0.")
        or dst_ip.startswith("239.255.")
    )

    if is_local_discovery:
        if pkts <= 8:
            return ProtocolValidationResult(
                verdict="VALID_BENIGN",
                protocol_name="Local Network Discovery (mDNS/LLMNR/SSDP)",
                is_protocol_compliant=True,
                should_suppress_alert=True,
                suggested_attack_type=None,
                suggested_severity="LOW",
                explanation=(
                    f"Local Link Protocol Validation: Standard discovery announcement ({pkts} packets, "
                    f"{total_bytes} bytes). Benign broadcast telemetry suppressed from false-alarm triage."
                ),
                evidence_telemetry=telemetry,
            )
        elif pkts >= 25 and packet_rate > 25.0:
            return ProtocolValidationResult(
                verdict="SUSPICIOUS_ANOMALY",
                protocol_name="Local Network Discovery (mDNS/LLMNR/SSDP)",
                is_protocol_compliant=False,
                should_suppress_alert=False,
                suggested_attack_type="Network Service Discovery Flood",
                suggested_severity="MEDIUM",
                explanation=(
                    f"Service Discovery Burst: Excessive multicast traffic ({pkts} packets at {packet_rate:.1f} pps). "
                    f"Potential local network enumeration or amplification probe."
                ),
                evidence_telemetry=telemetry,
            )

    # =========================================================================
    # 3. Standard DNS Query Validation (RFC 1035 - UDP Port 53)
    # =========================================================================
    is_dns = proto == "UDP" and (src_port == 53 or dst_port == 53)
    if is_dns:
        if pkts <= 8 and avg_pkt_size <= 600:
            return ProtocolValidationResult(
                verdict="VALID_BENIGN",
                protocol_name="DNS (RFC 1035)",
                is_protocol_compliant=True,
                should_suppress_alert=True,
                suggested_attack_type=None,
                suggested_severity="LOW",
                explanation=(
                    f"RFC 1035 DNS Validation: Standard resolver lookup ({pkts} packets, avg {avg_pkt_size:.0f} bytes)."
                ),
                evidence_telemetry=telemetry,
            )
        elif pkts >= 25 and packet_rate > 35.0:
            return ProtocolValidationResult(
                verdict="CONFIRMED_ATTACK",
                protocol_name="DNS (RFC 1035)",
                is_protocol_compliant=False,
                should_suppress_alert=False,
                suggested_attack_type="DNS Amplification / Flooding",
                suggested_severity="HIGH",
                explanation=(
                    f"DNS Flood Anomaly: Elevated volume ({pkts} packets at {packet_rate:.1f} pps). "
                    f"Matches DNS amplification or query flood signature."
                ),
                evidence_telemetry=telemetry,
            )

    # =========================================================================
    # 4. Default Pass-Through for General Network Flows
    # =========================================================================
    return ProtocolValidationResult(
        verdict="UNVERIFIED",
        protocol_name=f"{proto} Transport",
        is_protocol_compliant=True,
        should_suppress_alert=False,
        suggested_attack_type=None,
        suggested_severity=None,
        explanation=f"Flow telemetry forwarded to ML and evidence classification ({proto} {src_port}->{dst_port}).",
        evidence_telemetry=telemetry,
    )
