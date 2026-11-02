"""
CyberSentinel-X - Active Firewall Blocklist & Intrusion Prevention (IPS) Manager.
================================================================================
Maintains an active, persistent perimeter blocklist of quarantined attacker IPs.

Core IPS Principles:
1. When an IP is BLOCKED by the analyst or autonomous policy:
   - Subsequent inbound packets from that IP are marked as 'BLOCKED / DROPPED'.
   - The system intercepts and drops the packet at the perimeter, incrementing 'packets_dropped'.
   - Inbound traffic from a blocked IP does NOT trigger duplicate critical alarms or panic alerts;
     instead, the system maintains status: 'CONTAINED / SHIELD_ACTIVE'.
2. Optionally invokes OS-level firewall (Windows 'netsh' or Linux 'iptables') if elevated permissions exist.
3. Persists blocked state to JSON disk storage to maintain chain-of-containment across restarts.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("cybersentinel.firewall")

STORAGE_PATH = Path(__file__).resolve().parent.parent / "evidence_storage" / "firewall_blocklist.json"


class FirewallBlocklistManager:
    """
    Thread-safe intrusion prevention blocklist manager.
    """

    def __init__(self, persistence_file: Path = STORAGE_PATH):
        self._lock = threading.RLock()
        self.persistence_file = persistence_file
        # Map: ip -> {ip, blocked_at, reason, incident_id, packets_dropped, last_dropped_at, os_rule_applied}
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self.total_dropped_packets: int = 0
        self._load_from_disk()

    def _load_from_disk(self) -> None:
        try:
            if self.persistence_file.exists():
                with open(self.persistence_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._blocked_ips = data.get("blocked_ips", {})
                        self.total_dropped_packets = int(data.get("total_dropped_packets", 0))
                        logger.info(f"Loaded {len(self._blocked_ips)} blocked IPs from persistent storage.")
        except Exception as exc:
            logger.warning(f"Could not load firewall blocklist from disk: {exc}")

    def _save_to_disk(self) -> None:
        try:
            self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "total_dropped_packets": self.total_dropped_packets,
                "blocked_ips": self._blocked_ips,
            }
            with open(self.persistence_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as exc:
            logger.warning(f"Could not save firewall blocklist to disk: {exc}")

    def is_blocked(self, ip: Optional[str]) -> bool:
        """Returns True if the source IP is actively in the firewall blocklist."""
        if not ip:
            return False
        clean = str(ip).strip()
        with self._lock:
            return clean in self._blocked_ips

    def block_ip(
        self,
        ip: str,
        reason: str = "Automated AI / Analyst Containment",
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Adds an IP to the active firewall blocklist and attempts OS firewall rule enforcement.
        """
        clean_ip = str(ip).strip()
        if not clean_ip or clean_ip in ("127.0.0.1", "::1", "localhost"):
            return {"status": "error", "message": "Cannot block loopback or empty address"}

        now_iso = datetime.now(timezone.utc).isoformat()
        os_rule_applied = False
        os_rule_msg = "Perimeter Software Drop Active"

        # Attempt OS-level Windows Firewall enforcement
        if platform.system() == "Windows":
            rule_name = f"CyberSentinel_Block_{clean_ip.replace('.', '_').replace(':', '_')}"
            try:
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={clean_ip}",
                    "enable=yes",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    os_rule_applied = True
                    os_rule_msg = f"Windows Firewall rule '{rule_name}' enforced"
                else:
                    os_rule_msg = f"User permission required for netsh: {res.stderr.strip() or 'Elevation needed'}"
            except Exception as e:
                os_rule_msg = f"Host firewall call skipped ({e})"
        elif platform.system() == "Linux":
            try:
                cmd = ["iptables", "-A", "INPUT", "-s", clean_ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    os_rule_applied = True
                    os_rule_msg = f"iptables DROP rule applied for {clean_ip}"
            except Exception as e:
                os_rule_msg = f"iptables call skipped ({e})"

        with self._lock:
            existing = self._blocked_ips.get(clean_ip, {})
            record = {
                "ip": clean_ip,
                "status": "BLOCKED",
                "blocked_at": existing.get("blocked_at", now_iso),
                "reason": reason,
                "incident_id": incident_id or existing.get("incident_id"),
                "packets_dropped": existing.get("packets_dropped", 0),
                "last_dropped_at": existing.get("last_dropped_at"),
                "os_rule_applied": os_rule_applied,
                "os_rule_msg": os_rule_msg,
            }
            self._blocked_ips[clean_ip] = record
            self._save_to_disk()

        logger.info(f"FirewallBlocklist: IP {clean_ip} is now BLOCKED. Reason: {reason} ({os_rule_msg})")
        return {"status": "success", "record": record}

    def unblock_ip(self, ip: str) -> Dict[str, Any]:
        """
        Removes an IP from the blocklist and cleans up OS-level firewall rules.
        """
        clean_ip = str(ip).strip()
        with self._lock:
            if clean_ip not in self._blocked_ips:
                return {"status": "not_found", "message": f"IP {clean_ip} is not currently blocked"}

            # Cleanup OS-level rule if Windows
            if platform.system() == "Windows":
                rule_name = f"CyberSentinel_Block_{clean_ip.replace('.', '_').replace(':', '_')}"
                try:
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                except Exception:
                    pass
            elif platform.system() == "Linux":
                try:
                    cmd = ["iptables", "-D", "INPUT", "-s", clean_ip, "-j", "DROP"]
                    subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                except Exception:
                    pass

            del self._blocked_ips[clean_ip]
            self._save_to_disk()

        logger.info(f"FirewallBlocklist: IP {clean_ip} UNBLOCKED and firewall rule deleted.")
        return {"status": "success", "message": f"IP {clean_ip} successfully unblocked"}

    def record_dropped_packet(self, ip: str, port: int = 0) -> int:
        """
        Increments the dropped packets counter for a blocked IP when inbound traffic is intercepted.
        """
        clean_ip = str(ip).strip()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.total_dropped_packets += 1
            if clean_ip in self._blocked_ips:
                self._blocked_ips[clean_ip]["packets_dropped"] += 1
                self._blocked_ips[clean_ip]["last_dropped_at"] = now_iso
                return self._blocked_ips[clean_ip]["packets_dropped"]
            return 1

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Returns a list of all currently blocked IP records."""
        with self._lock:
            return list(self._blocked_ips.values())

    def get_stats(self) -> Dict[str, Any]:
        """Returns comprehensive summary of firewall block status."""
        with self._lock:
            active_count = len(self._blocked_ips)
            return {
                "active_blocks_count": active_count,
                "total_dropped_packets": self.total_dropped_packets,
                "blocked_ips": list(self._blocked_ips.keys()),
                "status": "ACTIVE" if active_count > 0 else "IDLE",
            }

    def clear_all(self) -> None:
        """Clears all blocks and resets drop counters."""
        with self._lock:
            # Delete any OS firewall rules
            if platform.system() == "Windows":
                for clean_ip in list(self._blocked_ips.keys()):
                    rule_name = f"CyberSentinel_Block_{clean_ip.replace('.', '_').replace(':', '_')}"
                    try:
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                            capture_output=True,
                            timeout=3,
                        )
                    except Exception:
                        pass
            self._blocked_ips.clear()
            self.total_dropped_packets = 0
            self._save_to_disk()
            logger.info("FirewallBlocklist: All IP blocks cleared.")


# Global singleton instance
firewall_blocklist = FirewallBlocklistManager()
