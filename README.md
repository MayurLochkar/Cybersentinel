# 🛡️ CyberSentinel-X
### Next-Generation Autonomous AI Cybersecurity Triage, Threat Detection & Cryptographic Evidence Hub

[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2016-black?style=flat&logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Random%20Forest%20(CICIDS2017)-F7931E?style=flat&logo=scikit-learn)](https://scikit-learn.org/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%2B%20SQLAlchemy-003B57?style=flat&logo=sqlite)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 📌 Project Overview

**CyberSentinel-X** is an end-to-end autonomous Security Operations Center (SOC) investigation platform designed to bridge machine learning network anomaly detection with intuitive cyber analyst workflows. 

It provides real-time threat detection, AI-driven forensic analysis, automated MITRE ATT&CK framework mapping, and SHA-256 cryptographic evidence tracking.

---

## ✨ Key Features

- **Autonomous Threat Classification**:
  - Live Random Forest classifier trained on the benchmark **CICIDS2017** dataset.
  - Distinguishes **BENIGN** network flows from attacks such as **DDoS, Port Scans, and Brute Force** with confidence percentages.
- **Interactive SOC Dashboard**:
  - Real-time KPIs for total alerts, high-risk triage, active investigations, and verified evidence integrity.
  - Live activity streams, severity filters, and attack vector breakdowns.
- **Incident Investigation & Forensics**:
  - Step-by-step autonomous reasoning lifecycle.
  - MITRE ATT&CK technique correlation (e.g., T1110 Brute Force, T1046 Network Service Scanning).
- **Cryptographic Evidence Verification**:
  - Tracks incident log integrity via SHA-256 hashing.
- **RESTful API Architecture**:
  - High-performance FastAPI backend with SQLAlchemy ORM and automatic SQLite persistence.
  - Interactive Swagger OpenAPI testing interface at `/docs`.

---

## 🏗️ System Architecture

```text
       ┌────────────────────────────────────────────────────────┐
       │                Next.js 16 (App Router)                 │
       │       - Tailwind CSS + Neumorphic Dark/Light Glass     │
       │       - Real-time Pollers & Interactive ML Tester      │
       └───────────────────────────┬────────────────────────────┘
                                   │ /api/proxy (Port 3000)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                    FastAPI Backend                     │
       │                   (Port 8000 / uvicorn)                │
       └─────────────┬───────────────────────────┬──────────────┘
                     │                           │
                     ▼                           ▼
       ┌───────────────────────────┐ ┌───────────────────────────┐
       │   SQLAlchemy + SQLite     │ │   Scikit-Learn ML Model   │
       │     - Incidents & Alerts  │ │     - Random Forest       │
       │     - Status Lifecycle    │ │     - CICIDS2017 Features │
       └───────────────────────────┘ └───────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** (v18+) & **npm**
- **Python** (v3.10+)

---

### 1. Backend Setup (FastAPI & ML Engine)

1. Open a terminal and navigate to `backend`:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install backend dependencies:
   ```bash
   pip install fastapi uvicorn sqlalchemy pydantic scikit-learn pandas numpy joblib
   ```

4. Start the FastAPI backend server:
   ```bash
   python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```
   - API will run at: `http://127.0.0.1:8000`
   - Swagger Documentation: `http://127.0.0.1:8000/docs`

---

### 2. Frontend Setup (Next.js)

1. Open a second terminal at the project root (`Cybersentinel`):
   ```bash
   npm install
   ```

2. Verify environment configuration:
   Ensure `.env.local` contains:
   ```env
   NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check for backend service |
| `GET` | `/api/dashboard/summary` | Real-time counts of total, critical, and active incidents |
| `GET` | `/api/alerts` | Fetch list of all active security alerts |
| `GET` | `/api/alerts/{incident_id}` | Retrieve specific incident details |
| `POST` | `/api/alerts` | Create and store a new incident |
| `PATCH` | `/api/alerts/{incident_id}/status` | Update incident status (`Open`, `Investigating`, `Resolved`) |
| `POST` | `/api/predict` | Run Random Forest inference on CICIDS2017 network flow features |

---

## 🧪 Testing Machine Learning Inference

You can run an automated prediction test directly from the command line:
```bash
cd backend
python ml/predict.py
```

Or execute inference via `curl`:
```bash
curl -X POST "http://127.0.0.1:8000/api/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "features": {
      "Destination Port": 80,
      "Flow Duration": 12933,
      "Total Fwd Packets": 3,
      "Total Backward Packets": 4,
      "Flow Bytes/s": 8994819.46,
      "Flow Packets/s": 541.25
    }
  }'
```

---

## 📦 Project Structure

```text
Cybersentinel/
├── app/                  # Next.js App Router (pages & global styling)
├── components/           # UI components, SOC Views & Visualizations
│   ├── dashboard/        # Views (Overview, Alerts, ML Performance, Forensics)
│   └── ui/               # Reusable UI primitives
├── data/                 # Baseline cyber telemetry data
├── lib/                  # Centralized API client & utility helpers
├── backend/
│   ├── main.py           # FastAPI entrypoint & REST routing
│   ├── models.py         # SQLAlchemy ORM models
│   ├── schemas.py        # Pydantic validation schemas
│   ├── database.py       # SQLite connection session setup
│   └── ml/
│       ├── train_model.py # Random Forest training script on CICIDS2017
│       ├── predict.py     # Inference pipeline & confidence scoring
│       └── models/        # Saved joblib model artifacts
└── README.md
```

---

## 📄 License
This project is licensed under the MIT License.
