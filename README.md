# 🛡️ CyberSentinel — Autonomous AI Cybersecurity Triage, Threat Detection & Cryptographic Evidence Hub

<div align="center">

**AI Network Anomaly Detection • RAG Forensic Synthesis • LangChain SOC Copilot • MITRE ATT&CK & NIST Response**

[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2015-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![LangChain](https://img.shields.io/badge/Agentics-LangChain%20%7C%20RAG-1C3C3C?style=for-the-badge&logo=chainlink)](https://www.langchain.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Random%20Forest%20(CICIDS2017)-F7931E?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org/)
[![Scapy](https://img.shields.io/badge/Sniffer-Scapy%20%7C%20PCAP-red?style=for-the-badge)](https://scapy.net/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2B%20SQLAlchemy-003B57?style=for-the-badge&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

</div>

---

## 📌 Executive Overview

**CyberSentinel** is an enterprise-grade autonomous Security Operations Center (SOC) investigation platform. It unites real-time packet-level network telemetry, machine learning anomaly detection, cryptographic evidence chain tracking, and **Retrieval-Augmented Generation (RAG) powered by LangChain** to deliver instantaneous, actionable cyber threat intelligence.

Whether ingesting live network packets via **Scapy**, processing multi-gigabyte **PCAP/PCAPNG** captures, or correlating suspicious flows against **MITRE ATT&CK** and **NIST SP 800-61 Rev. 2** response playbooks, CyberSentinel provides security analysts with an end-to-end tactical defense console.

---

## ⚡ Core Capabilities & Highlights

### 1. 🧠 RAG & LangChain Multi-Provider SOC Copilot
- **Semantic Vector Retrieval**: High-speed TF-IDF and Cosine vector search indexing the MITRE ATT&CK knowledge base, tactics, techniques, and NIST containment procedures.
- **Multi-Provider LLM Integration**: Natively supports **LangChain** with **Google Gemini (gemini-1.5-flash)**, **OpenAI (gpt-4o-mini)**, or local HuggingFace/Ollama models.
- **Autonomous Deterministic Fallback**: Operates at **zero API cost** completely offline when API keys are absent, delivering reliable, forensically sound intelligence.
- **Interactive Analyst Copilot**: Real-time Q&A assistant to query attack vectors, explain raw flow anomalies, draft executive incident briefings, and synthesize remediation steps.
- **Instant Containment & Rule Generation**: Automatically generates host isolation commands, firewall syntax (`iptables`), and intrusion detection rules (`Snort` / `Suricata`).

### 2. 🛰️ Real-Time Packet Sniffer & PCAP Stream Ingestion
- **Live Scapy Sniffing**: Continuous real-time packet capture with interface enumeration, WinPcap/Npcap driver binding, and dynamic packet throttling.
- **Chunked 12+ GB PCAP Streaming**: Disk-buffered chunked streaming upload handles massive packet capture files without exhausting RAM.
- **70-Feature Flow Aggregator**: Reconstructs bidirectional flows with rolling mean, stddev, packet duration, inter-arrival time (IAT), flag frequencies, and header lengths.

### 3. 🎯 Machine Learning Flow Classifier (CICIDS2017)
- **Random Forest Model**: Trained on the benchmark **CICIDS2017** dataset to classify flows as **BENIGN** or **ATTACK** (DDoS, SYN Flood, Port Scans, Brute Force).
- **High-Speed Vectorized Batch Inferences**: Evaluates thousands of network flows in parallel with microsecond response times and probabilistic confidence scores.

### 4. 🔒 Cryptographic SHA-256 Forensic Evidence Ledger
- **Tamper-Evident Storage**: Forensic PCAP slices and log files are stamped with immutable SHA-256 hashes upon capture.
- **One-Click Integrity Verification**: Validates disk artifacts against the tamper-evident ledger to ensure legal chain of custody.

### 5. 💻 Tactical SOC Dashboard
- **Glassmorphic Cyber Aesthetic**: High-contrast dark and light command center with tactical cyber cursor, ambient lighting, and micro-interactions.
- **Modular SOC Views**: Overview, Real-Time Monitoring, Alerts Matrix, Investigation Copilot, Evidence Verification, Analytics, and Threat Intel Lookup.

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│              Next.js 15 Tactical Frontend Dashboard                    │
│   - Glassmorphic Neumorphic UI     - Real-Time Telemetry Pollers       │
│   - Interactive RAG AI Copilot     - Live PCAP Stream & Alerts Matrix  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST (/api/...)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   FastAPI High-Performance Backend                     │
├───────────────────────────────────┬────────────────────────────────────┤
│  🛰️ Monitoring & Ingestion        │  🧠 AI Copilot & Knowledge         │
│  - Scapy Live Packet Sniffer      │  - LangChain Agentic Chains        │
│  - Chunked Streaming PCAP Parser  │  - Semantic Vector RAG Retriever   │
│  - 70-Feature Flow Extractor      │  - MITRE ATT&CK & NIST Playbooks   │
├───────────────────────────────────┼────────────────────────────────────┤
│  🎯 ML Classification Engine      │  🔒 Cryptographic Forensic Ledger  │
│  - Random Forest (CICIDS2017)     │  - SHA-256 Disk Hash Verifier      │
│  - Vectorized Batch Inferences    │  - Immutable Audit Catalog         │
└───────────────────┬───────────────┴────────────────────┬───────────────┘
                    │                                    │
                    ▼                                    ▼
       ┌──────────────────────────┐         ┌──────────────────────────┐
       │   SQLAlchemy + SQLite    │         │  Forensic Evidence Disk  │
       │  - Alerts & Incidents    │         │  - Raw PCAP Captures     │
       │  - Telemetry Sessions    │         │  - Ledger Catalog JSON   │
       └──────────────────────────┘         └──────────────────────────┘
```

---

## 📂 Repository Structure

```text
Cybersentinel/
├── app/                              # Next.js App Router (Layouts & Pages)
│   ├── globals.css                   # Custom neumorphic styles & design tokens
│   ├── layout.tsx                    # Root layout with fonts & metadata
│   ├── page.tsx                      # Dashboard root entrypoint
│   └── monitoring/                   # Real-time network telemetry view
├── components/                       # Dashboard UI & Tactical Components
│   ├── dashboard/                    # Core SOC command layouts
│   │   ├── centered-command-nav.tsx  # Quick navigation switcher
│   │   ├── dashboard-layout.tsx      # Main stateful dashboard controller
│   │   ├── evidence-modal.tsx        # Cryptographic verification viewer
│   │   ├── how-it-works-modal.tsx    # Technical architectural guide
│   │   ├── sidebar.tsx               # Primary SOC sidebar
│   │   ├── top-navbar.tsx            # Header with health status & controls
│   │   └── views/                    # SOC Operational Views
│   │       ├── alert-details-view.tsx
│   │       ├── alerts-view.tsx       # Live incident triage matrix
│   │       ├── analytics-view.tsx    # Attack distribution & trends
│   │       ├── evidence-view.tsx     # SHA-256 chain of custody audit
│   │       ├── investigation-view.tsx # RAG & LangChain AI Copilot View
│   │       ├── monitoring-view.tsx   # Live packet capture & PCAP ingestion
│   │       ├── overview-view.tsx     # High-level KPIs and incident stats
│   │       ├── risk-view.tsx         # Automated risk scoring & MITRE mapping
│   │       └── threat-intel-view.tsx # Reputation search & indicators
│   └── ui/                           # Reusable UI primitives & cyber cursor
├── backend/                          # FastAPI Backend & Intelligence Services
│   ├── main.py                       # Application entrypoint & REST API endpoints
│   ├── rag_copilot.py                # RAG Vector Store, LangChain & AI Copilot
│   ├── models.py                     # SQLAlchemy database models
│   ├── schemas.py                    # Pydantic input/output validation schemas
│   ├── database.py                   # SQLite engine session management
│   ├── requirements.txt              # Python production dependencies
│   ├── init_evidence.py              # Forensic catalog initializer
│   ├── trigger_real_attack.py        # Real attack traffic generator (SYN Flood)
│   ├── test_monitoring.py            # Comprehensive 12-stage test suite
│   ├── test_regression_audit.py      # Edge case & flow aggregator verification
│   ├── evidence_storage/             # Cryptographic ledger & sample artifacts
│   ├── ml/                           # Machine Learning Pipeline
│   │   ├── predict.py                # 70-feature Random Forest inference engine
│   │   ├── train_model.py            # Model training script for CICIDS2017
│   │   └── models/                   # Serialized model artifact (.joblib)
│   └── monitoring/                   # Live Network Capture & PCAP Aggregator
│       ├── flow_extractor.py         # 70-feature bidirectional flow engine
│       ├── live_capture.py           # Scapy live packet capture thread
│       ├── manager.py                # Singleton monitoring session manager
│       ├── pcap_processor.py         # Fast streaming PCAP/PCAPNG ingestor
│       └── sample_pcap.py            # Synthetic PCAP generator for testing
├── data/                             # Baseline cyber data & definitions
├── lib/                              # Centralized API client & utility helpers
│   ├── api.ts                        # Complete TypeScript API client
│   └── utils.ts                      # CSS class concatenation helpers
├── .env.example                      # Template for environment variables
└── README.md                         # Project documentation
```

---

## 🚀 Quickstart Guide

### Prerequisites
- **Node.js** (v18+) & **npm**
- **Python** (v3.10+)
- *(Optional)* Npcap / WinPcap installed for live packet sniffing on Windows

---

### Step 1: Backend Setup (FastAPI & ML Engine)

1. Open a terminal and navigate to `backend/`:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. *(Optional)* Configure AI Copilot API keys by copying `.env.example`:
   ```bash
   cp ../.env.example .env
   ```
   *Note: If `OPENAI_API_KEY` or `GEMINI_API_KEY` is not provided, CyberSentinel automatically utilizes its built-in local deterministic RAG engine without error.*

5. Start the backend service:
   ```bash
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
   - Swagger OpenAPI Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - Health Endpoint: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

### Step 2: Frontend Setup (Next.js 15)

1. Open a new terminal in the project root (`Cybersentinel/`):
   ```bash
   npm install
   ```

2. Launch the Next.js development server:
   ```bash
   npm run dev
   ```

3. Open your browser at [http://localhost:3000](http://localhost:3000).

---

## 📡 API Reference

### RAG & LangChain AI Copilot
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/ai/investigate` | Runs RAG incident investigation against MITRE ATT&CK & NIST playbooks |
| `POST` | `/api/ai/copilot-chat` | Interactive SOC Analyst Q&A chat grounded in live incident telemetry |
| `GET` | `/api/ai/knowledge-stats` | Returns indexed MITRE techniques count and active LLM provider |

### Machine Learning & Threat Detection
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/predict` | Evaluates 70 CICIDS2017 flow features using Random Forest |
| `GET` | `/api/alerts` | Fetches all detected security incidents and triage status |
| `GET` | `/api/alerts/{id}` | Retrieves detailed telemetry and forensic facts for an incident |
| `PATCH` | `/api/alerts/{id}/status` | Updates incident lifecycle (`Open`, `Investigating`, `Resolved`) |

### Real-Time Network Monitoring & PCAP Ingestion
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/monitoring/status` | Active capture status, packet counts, and flow rates |
| `GET` | `/api/monitoring/metrics` | Processed flows, benign/attack tallies, and recent flow streams |
| `GET` | `/api/monitoring/interfaces` | Enumerates available host network interfaces & driver status |
| `POST` | `/api/monitoring/start` | Starts authorized live Scapy packet capture on chosen adapter |
| `POST` | `/api/monitoring/stop` | Halts live packet capture cleanly |
| `POST` | `/api/monitoring/pcap` | Uploads and processes a PCAP/PCAPNG capture file |
| `POST` | `/api/monitoring/pcap/local` | Streams large local PCAP file directly from disk without upload latency |
| `GET` | `/api/monitoring/sample-pcap` | Downloads a synthetic PCAP sample for pipeline verification |
| `POST` | `/api/monitoring/reset` | Resets active telemetry session counters back to 0 |
| `GET` | `/api/monitoring/history` | Returns the audit ledger of past monitoring sessions and uploads |

### Cryptographic Evidence Integrity
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/evidence` | Lists all evidence artifacts, stored hashes, and file metadata |
| `POST` | `/api/evidence/verify` | Recomputes SHA-256 hash on disk and confirms tamper-evident validity |

---

## 🧪 Testing & Verification Suites

### 1. End-to-End Pipeline Audit
Runs an automated 12-stage test covering API health, ML inference, PCAP ingestion, interface discovery, and live capture:
```bash
cd backend
python test_monitoring.py
```

### 2. Regression & Flow Aggregation Audit
Validates edge-case flow timeouts, TCP teardown handshakes (FIN/ACK), straggler absorption, and bidirectional metrics:
```bash
cd backend
python test_regression_audit.py
```

### 3. Real Attack Traffic Simulation
Generates genuine TCP SYN Flood attack packets against a local test port to demonstrate real-time detection, feature extraction, and ML alert generation:
```bash
cd backend
python trigger_real_attack.py
```

---

## 🛡️ MITRE ATT&CK Framework Mapping

CyberSentinel dynamically correlates detected network anomalies to established MITRE techniques:

| Technique ID | Technique Name | Tactic | Primary Indicators |
|---|---|---|---|
| **T1110** | Brute Force / Credential Stuffing | Credential Access | High SYN frequency on auth ports (22, 3389, 443, 8080) with rapid RST responses |
| **T1498** | Network Denial of Service (DoS/DDoS) | Impact | Asymmetric SYN-to-ACK ratio, volumetric packet spikes, depleted window sizes |
| **T1046** | Network Service Discovery / Port Scan | Discovery | Sequential connection attempts across distinct ports in microsecond intervals |
| **T1071** | Application Layer Protocol C2 | Command and Control | Periodic jittered beaconing, anomalous headers, high-entropy DNS query sizes |
| **T1190** | Exploit Public-Facing Application | Initial Access | Payload signatures in request URI/body, HTTP 4xx/5xx error anomalies |

---

## 📄 License
This project is licensed under the **MIT License**.
