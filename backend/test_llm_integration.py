import os
import sys
import requests
import json
import time
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=env_path)
except Exception:
    pass

API_KEY = os.getenv("GEMINI_API_KEY", "")
candidate_models = [
    os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite"),
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-3.8-flash",
]

payload = {
    "contents": [
        {
            "parts": [
                {"text": "Confirm in 5 words that CyberSentinel AI is online."}
            ]
        }
    ]
}
headers = {"Content-Type": "application/json"}

print("=" * 60)
print("   CyberSentinel-X LLM Integration & Provider Diagnostic")
print("=" * 60)
print(f"[*] API Key Present: {'Yes' if API_KEY else 'No'}")

success = False
for model in candidate_models:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={API_KEY}"
    print(f"\n[*] Probing Gemini model '{model}' (10s timeout)...", flush=True)
    t0 = time.time()
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=10)
        elapsed = time.time() - t0
        print(f"    HTTP Status: {res.status_code} in {elapsed:.2f}s", flush=True)
        if res.status_code == 200:
            data = res.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            print(f"    [REAL GEMINI RESPONSE]:\n    {text.strip()}\n", flush=True)
            success = True
            break
        else:
            print(f"    Model '{model}' response: {res.text[:200]}...", flush=True)
    except requests.exceptions.Timeout:
        print(f"    [!] Timeout reached on '{model}' (>10s).", flush=True)
    except Exception as e:
        print(f"    [!] Connection error on '{model}': {e}", flush=True)

if not success:
    print("\n[INFO] Remote LLM provider timed out or restricted.")
    print("[INFO] Testing CyberSentinel Deterministic Fallback Engine (Local SOC Knowledge Base)...")
    try:
        from rag_copilot import chat_with_copilot_rag
        fallback_resp = chat_with_copilot_rag("Is CyberSentinel AI online?")
        print(f"[+] Fallback Provider: {fallback_resp.get('provider')}")
        print(f"[+] Output: {fallback_resp.get('response')[:150]}...")
        print("[SUCCESS] Local offline fallback engine is active and 100% operational.")
    except Exception as e:
        print(f"[-] Fallback error: {e}")

print("=" * 60)
