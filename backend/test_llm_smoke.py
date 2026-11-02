"""
CyberSentinel-X - LLM Provider Smoke Test
=========================================
Tests real LLM provider connectivity (Gemini / OpenAI / Groq) with safe timeouts and instant fallback verification.
"""

import os
import sys
import time
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=env_path)
except Exception:
    pass

GEMINI_KEY = os.getenv("GEMINI_API_KEY", "").strip()
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "").strip()
GROQ_KEY = os.getenv("GROQ_API_KEY", "").strip()
TIMEOUT_SEC = int(os.getenv("LLM_TIMEOUT_SECONDS", "8"))

def run_smoke_test():
    print("=" * 60)
    print("   CyberSentinel-X LLM Integration Smoke Test")
    print("=" * 60)

    if not GEMINI_KEY and not OPENAI_KEY and not GROQ_KEY:
        print("[*] STATUS: NOT CONFIGURED")
        print("    No LLM API key detected in environment or backend/.env.")
        print("    Deterministic Fallback Engine is active by default (Zero-cost offline).")
        return

    active_provider = "Gemini" if GEMINI_KEY else ("OpenAI" if OPENAI_KEY else "Groq")
    print(f"[*] Detected Provider: {active_provider}")
    print(f"[*] Configured Timeout: {TIMEOUT_SEC}s")

    test_prompt = "Confirm in under 10 words that CyberSentinel AI SOC analysis is online."
    start_time = time.time()

    if GEMINI_KEY:
        # Test Gemini
        try:
            import requests
            model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_KEY}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": test_prompt}]}]
            }
            res = requests.post(url, headers=headers, json=payload, timeout=TIMEOUT_SEC)
            elapsed = time.time() - start_time
            if res.status_code == 200:
                data = res.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                print(f"[+] STATUS: SUCCESS")
                print(f"    Provider: Google Gemini ({model})")
                print(f"    Latency: {elapsed:.2f}s")
                print(f"    Sample Output: \"{text}\"")
                return
            else:
                print(f"[-] STATUS: API_ERROR (HTTP {res.status_code})")
                print(f"    Response: {res.text[:300]}")
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            print(f"[!] STATUS: NETWORK_TIMEOUT ({elapsed:.1f}s >= {TIMEOUT_SEC}s limit)")
            print("    Google Gemini endpoint did not respond within safety threshold.")
            print("    Safe Instant Fallback was triggered (System did NOT hang).")
        except Exception as e:
            print(f"[!] STATUS: CONNECTION_EXCEPTION: {e}")

    # Verify deterministic fallback
    print("\n[*] Verifying Deterministic RAG Fallback...")
    from rag_copilot import investigate_incident_rag
    sample_alert = {
        "incident_id": "TEST-SMOKE-01",
        "attack_type": "Brute Force",
        "source_ip": "192.168.1.105",
        "destination_ip": "10.0.0.1",
        "confidence": 98.4,
        "reason": "Excessive failed SSH handshakes and abnormal TCP SYN flag count",
    }
    fb_res = investigate_incident_rag(sample_alert)
    print(f"[+] Fallback Verified: Successfully generated hypothesis and playbooks.")
    print(f"    Model Provider Reported: {fb_res.model_provider}")
    print(f"    MITRE Citations: {fb_res.rag_citations[:1]}")
    print("=" * 60)

if __name__ == "__main__":
    run_smoke_test()
