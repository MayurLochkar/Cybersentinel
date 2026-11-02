"""
CyberSentinel-X - Instant Live Attack Generator
===============================================
Run this script to demonstrate real-time attack detection to your mentor in 1 click!

Modes:
1. Port Scan Simulation (Sends rapid TCP SYN packets across ports)
2. Live Attack Injection (Immediately creates a High-Confidence Malicious Alert in Dashboard)
3. Sample PCAP Trigger (Feeds real CICIDS2017 attack flows to the Random Forest model)
"""

import sys
import time
import requests
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000"

def trigger_alert_injection(source_ip: str = "192.168.29.127"):
    print(f"[*] Triggering Live Attack Burst from Attacker ({source_ip}) -> Host (192.168.29.93:8000)...", flush=True)
    try:
        res = requests.get(f"{BASE_URL}/api/monitoring/simulate_burst?source_ip={source_ip}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            print(f"[+] SUCCESS: Live Attack Incident Created!")
            print(f"    Attacker IP   : {data.get('source_ip')}")
            print(f"    Target Asset  : {data.get('target_ip')}:{data.get('target_port')}")
            print(f"    Attack Status : {data.get('message')}")
            print("\n[-->] Check your browser dashboard at http://localhost:3000/ - All features are now live!")
        else:
            print(f"[-] Failed to trigger burst: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[-] Error connecting to backend: {e}")

def trigger_pcap_sample():
    print("[*] Ingesting Sample PCAP Attack Stream into Scapy Flow Classifier...", flush=True)
    try:
        res = requests.post(f"{BASE_URL}/api/monitoring/sample-pcap", timeout=10)
        if res.status_code in (200, 201):
            data = res.json()
            print(f"[+] SUCCESS: Extracted {data.get('flows_extracted')} flows!")
            print(f"    Attacks Detected: {data.get('attack_flows')}")
            print(f"    Benign Flows: {data.get('benign_flows')}")
            print(f"    Alerts Created: {data.get('alerts_created')}")
            print("\n[-->] Refresh Alerts / Dashboard to see the classified flows!")
        else:
            print(f"[-] Error: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[-] Connection Error: {e}")

def trigger_real_scapy_packets():
    print("[*] Sending real local TCP probe packets via Scapy...", flush=True)
    try:
        from scapy.all import IP, TCP, send
        target_ip = "127.0.0.1"
        ports = [21, 22, 23, 25, 80, 110, 443, 3306, 8080]
        print(f"[*] Scanning {len(ports)} ports on {target_ip} with TCP SYN packets...")
        for p in ports:
            pkt = IP(dst=target_ip) / TCP(dport=p, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.05)
        print("[+] SUCCESS: Rapid SYN scan packets transmitted to local network stack!")
    except Exception as e:
        print(f"[-] Scapy transmission note: {e}")
        print("    Falling back to instant Alert Injection...")
        trigger_alert_injection()

if __name__ == "__main__":
    print("=" * 60)
    print("   CyberSentinel-X - Instant Live Attack Generator")
    print("=" * 60)
    print("1. Inject High-Severity Attack Alert into Dashboard (Fastest & 100% Reliable)")
    print("2. Run Sample PCAP Flow Analyzer (Extracts 70 features & ML inference)")
    print("3. Send Real TCP SYN Probe Packets via Network Stack")
    print("=" * 60)
    
    choice = input("Enter choice (1, 2, or 3) [Default: 1]: ").strip()
    if choice == "2":
        trigger_pcap_sample()
    elif choice == "3":
        trigger_real_scapy_packets()
    else:
        trigger_alert_injection()
