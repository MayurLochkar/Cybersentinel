import hashlib
import json
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Response, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Alert
from schemas import (
    AlertCreate,
    AlertResponse,
    AlertStatusUpdate,
    EvidenceItemSchema,
    EvidenceVerifyRequest,
    EvidenceVerifyResponse,
    AnalyticsSummaryResponse,
    RiskSummaryResponse,
    IncidentRiskSchema,
    RiskFactorSchema,
)
from pydantic import BaseModel, Field
from ml.predict import predict_traffic
from monitoring.manager import monitoring_manager
from monitoring.live_capture import get_available_interfaces, is_pcap_available
from monitoring.pcap_processor import PcapValidationError
from monitoring.sample_pcap import generate_sample_pcap_bytes
from rag_copilot import (
    investigate_incident_rag,
    chat_with_copilot_rag,
    CYBER_KNOWLEDGE_BASE,
    AICopilotQuery,
    AIInvestigationResponse,
)

EVIDENCE_DIR = Path(__file__).resolve().parent / "evidence_storage"
EVIDENCE_CATALOG_FILE = EVIDENCE_DIR / "ledger_catalog.json"


def get_verified_evidence_count() -> int:
    """Computes genuine count of forensic evidence files on disk whose SHA-256 matches stored hash."""
    if not EVIDENCE_CATALOG_FILE.exists():
        return 0
    try:
        with open(EVIDENCE_CATALOG_FILE, "r", encoding="utf-8") as f:
            catalog = json.load(f)
        count = 0
        for item in catalog:
            file_path = EVIDENCE_DIR / item.get("file_name", "")
            if file_path.is_file():
                current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
                if current_hash.lower() == item.get("stored_hash", "").lower():
                    count += 1
        return count
    except Exception:
        return 0


def seed_demo_data():
    """Insert clearly labelled demo incidents only when the table is empty."""
    with Session(engine) as db:
        existing = db.scalar(select(func.count()).select_from(Alert))

        if existing:
            return

        now = datetime.now(timezone.utc).isoformat()

        demo_alerts = [
            Alert(
                incident_id="INC-1024",
                attack_type="Brute Force",
                source_ip="185.73.21.10",
                destination_ip="10.0.0.21",
                target="Auth Server",
                severity="HIGH",
                confidence=94.2,
                status="Investigating",
                reason=(
                    "DEMO: Repeated authentication attempts "
                    "within a short time window."
                ),
                created_at=now,
            ),
            Alert(
                incident_id="INC-1023",
                attack_type="Port Scan",
                source_ip="45.91.22.17",
                destination_ip="10.0.0.15",
                target="Web Server",
                severity="MEDIUM",
                confidence=91.7,
                status="Open",
                reason=(
                    "DEMO: Traffic pattern resembles "
                    "a port-scanning activity."
                ),
                created_at=now,
            ),
            Alert(
                incident_id="INC-1022",
                attack_type="DDoS",
                source_ip="103.44.18.91",
                destination_ip="10.0.0.8",
                target="API Gateway",
                severity="CRITICAL",
                confidence=98.1,
                status="Investigating",
                reason=(
                    "DEMO: Unusually high request volume "
                    "in a short period."
                ),
                created_at=now,
            ),
        ]

        db.add_all(demo_alerts)
        db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    seed_demo_data()
    # Pre-warm Random Forest ML model into memory so first inference is instant
    try:
        from ml.predict import load_model
        load_model()
    except Exception:
        pass
    yield
    try:
        monitoring_manager.stop_monitoring()
    except Exception:
        pass


class TrafficPredictionRequest(BaseModel):
    features: dict[str, float] = Field(
        ...,
        description="Numeric CICIDS2017 network-flow features",
    )


class MonitoringStartRequest(BaseModel):
    interface: str | None = None
    bpf_filter: str | None = None
    mode: str | None = "real"


app = FastAPI(
    title="CyberSentinel-X API",
    description="Cybersecurity investigation backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "project": "CyberSentinel-X",
        "message": "Backend is running",
    }


@app.get("/api/health")
def health():
    return {"status": "operational"}


@app.get("/api/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(Alert)) or 0

    critical = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.severity == "CRITICAL"
        )
    ) or 0

    high_risk = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.severity.in_(["HIGH", "CRITICAL"])
        )
    ) or 0

    active = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.status == "Investigating"
        )
    ) or 0

    open_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.status == "Open"
        )
    ) or 0

    resolved_alerts = db.scalar(
        select(func.count()).select_from(Alert).where(
            Alert.status == "Resolved"
        )
    ) or 0

    verified_count = get_verified_evidence_count()

    mon_metrics = monitoring_manager.get_metrics()
    mon_status = monitoring_manager.get_status()

    return {
        "total_alerts": total,
        "critical": critical,
        "high_risk": high_risk,
        "active_investigations": active,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "verified_evidence": verified_count,
        "data_source": "SQLite & Forensic Evidence Ledger",
        "monitoring_status": mon_status.get("status", "STOPPED"),
        "capture_mode": mon_status.get("capture_mode", "idle"),
        "source": mon_status.get("source") or "None",
        "flows_processed": mon_metrics.get("flows_processed", 0),
        "packets_captured": mon_metrics.get("packets_captured", 0),
        "benign_count": mon_metrics.get("benign_count", 0),
        "attack_count": mon_metrics.get("attack_count", 0),
        "monitoring_alerts": mon_metrics.get("alerts_created", 0),
    }


@app.get("/api/analytics/summary", response_model=AnalyticsSummaryResponse)
def get_analytics_summary(db: Session = Depends(get_db)):
    alerts = db.scalars(select(Alert)).all()
    total = len(alerts)

    attack_counts: dict[str, int] = {}
    for a in alerts:
        atype = a.attack_type or "Unknown"
        attack_counts[atype] = attack_counts.get(atype, 0) + 1

    attack_colors = {
        "Brute Force": "#ef4444",
        "Port Scan": "#3b82f6",
        "DDoS": "#8b5cf6",
        "Infiltration": "#f59e0b",
        "Probe": "#06b6d4",
        "SQL Injection": "#ec4899",
        "API Contract Verification Probe": "#10b981",
        "Botnet": "#6366f1",
    }
    fallback_palette = ["#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6", "#06b6d4", "#ec4899"]

    attack_distribution = []
    idx = 0
    for name, cnt in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
        color = attack_colors.get(name, fallback_palette[idx % len(fallback_palette)])
        idx += 1
        pct = round((cnt / total * 100), 1) if total > 0 else 0.0
        attack_distribution.append({
            "name": name,
            "value": cnt,
            "percentage": pct,
            "color": color,
        })

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = (a.severity or "MEDIUM").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["MEDIUM"] += 1

    risk_distribution = [
        {"name": "Critical", "value": sev_counts["CRITICAL"], "color": "#ef4444"},
        {"name": "High", "value": sev_counts["HIGH"], "color": "#f97316"},
        {"name": "Medium", "value": sev_counts["MEDIUM"], "color": "#eab308"},
        {"name": "Low", "value": sev_counts["LOW"], "color": "#3b82f6"},
    ]

    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    day_counts = {d: 0 for d in days}
    for a in alerts:
        try:
            clean_ts = a.created_at.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            day_name = days[dt.weekday()]
            day_counts[day_name] += 1
        except Exception:
            day_counts["Wed"] += 1

    weekly_activity = [{"day": d, "incidents": day_counts[d]} for d in days]

    src_counts: dict[str, int] = {}
    for a in alerts:
        ip = a.source_ip or "Unknown"
        src_counts[ip] = src_counts.get(ip, 0) + 1
    top_source_ips = [
        {"ip": ip, "count": cnt}
        for ip, cnt in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    tgt_counts: dict[str, int] = {}
    for a in alerts:
        tgt = a.target or "General Host"
        tgt_counts[tgt] = tgt_counts.get(tgt, 0) + 1
    top_targets = [
        {"target": tgt, "count": cnt}
        for tgt, cnt in sorted(tgt_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    status_counts = {"Open": 0, "Investigating": 0, "Resolved": 0}
    for a in alerts:
        st = a.status or "Open"
        if st in status_counts:
            status_counts[st] += 1
        else:
            status_counts["Open"] += 1

    return {
        "total_alerts": total,
        "attack_distribution": attack_distribution,
        "risk_distribution": risk_distribution,
        "weekly_activity": weekly_activity,
        "top_source_ips": top_source_ips,
        "top_targets": top_targets,
        "status_pipeline": status_counts,
    }


@app.get("/api/risk/summary", response_model=RiskSummaryResponse)
def get_risk_summary(db: Session = Depends(get_db)):
    alerts = db.scalars(select(Alert).order_by(Alert.id.desc())).all()

    def get_target_criticality(tgt: str) -> float:
        t = (tgt or "").lower()
        if any(k in t for k in ["auth", "gateway", "db", "database", "api"]):
            return 90.0
        if any(k in t for k in ["web", "ingress", "frontend"]):
            return 75.0
        return 60.0

    sev_scores = {
        "CRITICAL": 95.0,
        "HIGH": 80.0,
        "MEDIUM": 55.0,
        "LOW": 25.0,
    }

    incidents_risk = []
    total_score = 0.0

    for a in alerts:
        sev = (a.severity or "MEDIUM").upper()
        s_score = sev_scores.get(sev, 50.0)
        c_score = min(100.0, max(0.0, float(a.confidence or 75.0)))
        t_score = get_target_criticality(a.target)

        calc_score = round(0.45 * s_score + 0.35 * c_score + 0.20 * t_score, 1)
        total_score += calc_score

        if calc_score >= 85.0:
            r_level = "CRITICAL"
        elif calc_score >= 70.0:
            r_level = "HIGH"
        elif calc_score >= 40.0:
            r_level = "MEDIUM"
        else:
            r_level = "LOW"

        factors = [
            {"name": "Threat Severity", "level": sev if sev in sev_scores else "MEDIUM", "score": s_score},
            {"name": "ML Confidence", "level": "HIGH" if c_score >= 80.0 else "MEDIUM", "score": c_score},
            {"name": "Asset Criticality", "level": "CRITICAL" if t_score >= 90.0 else "HIGH" if t_score >= 75.0 else "MEDIUM", "score": t_score},
        ]

        explanation = (
            f"Evaluated via formula (0.45*Severity + 0.35*Confidence + 0.20*AssetCriticality). "
            f"Target '{a.target}' weighted at criticality {t_score}."
        )

        incidents_risk.append({
            "incident_id": a.incident_id,
            "attack_type": a.attack_type,
            "severity": a.severity,
            "confidence": a.confidence,
            "calculated_risk_score": calc_score,
            "risk_level": r_level,
            "factors": factors,
            "explanation": explanation,
        })

    overall_score = round(total_score / len(alerts), 1) if alerts else 0.0
    if overall_score >= 85.0:
        overall_level = "CRITICAL"
    elif overall_score >= 70.0:
        overall_level = "HIGH"
    elif overall_score >= 40.0:
        overall_level = "MEDIUM"
    else:
        overall_level = "LOW"

    return {
        "overall_score": overall_score,
        "overall_level": overall_level,
        "scoring_formula": "0.45 * ThreatSeverity + 0.35 * MLConfidence + 0.20 * AssetCriticality",
        "incidents": incidents_risk,
    }


@app.get("/api/evidence", response_model=list[EvidenceItemSchema])
def list_evidence():
    if not EVIDENCE_CATALOG_FILE.exists():
        return []
    with open(EVIDENCE_CATALOG_FILE, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    results = []
    for item in catalog:
        file_path = EVIDENCE_DIR / item.get("file_name", "")
        if not file_path.is_file():
            ver_status = "MISSING"
        else:
            current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
            if current_hash.lower() == item.get("stored_hash", "").lower():
                ver_status = "VERIFIED"
            else:
                ver_status = "TAMPERED"

        results.append({
            "id": item["id"],
            "file_name": item["file_name"],
            "incident_id": item["incident_id"],
            "stored_hash": item["stored_hash"],
            "file_size": item.get("file_size", "Unknown"),
            "blockchain_status": item.get("blockchain_status", "Recorded"),
            "verification_status": ver_status,
            "timestamp": item.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "recorded_block": item.get("recorded_block", None),
        })

    return results


@app.post("/api/evidence/verify", response_model=EvidenceVerifyResponse)
def verify_evidence(payload: EvidenceVerifyRequest):
    if not EVIDENCE_CATALOG_FILE.exists():
        raise HTTPException(status_code=404, detail="Evidence catalog not found")

    with open(EVIDENCE_CATALOG_FILE, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    item = next((x for x in catalog if x.get("id") == payload.evidence_id), None)
    if not item:
        raise HTTPException(status_code=404, detail=f"Evidence ID {payload.evidence_id} not found in ledger")

    file_path = EVIDENCE_DIR / item.get("file_name", "")
    now_iso = datetime.now(timezone.utc).isoformat()

    if not file_path.is_file():
        return {
            "evidence_id": item["id"],
            "file_name": item["file_name"],
            "stored_hash": item["stored_hash"],
            "current_hash": "FILE_NOT_FOUND",
            "verification_status": "MISSING",
            "message": f"Artifact '{item['file_name']}' is missing from forensic evidence storage on disk.",
            "timestamp": now_iso,
        }

    current_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
    if current_hash.lower() == item.get("stored_hash", "").lower():
        return {
            "evidence_id": item["id"],
            "file_name": item["file_name"],
            "stored_hash": item["stored_hash"],
            "current_hash": current_hash,
            "verification_status": "VERIFIED",
            "message": "SHA-256 integrity match verified. Byte stream matches recorded forensic ledger hash.",
            "timestamp": now_iso,
        }
    else:
        return {
            "evidence_id": item["id"],
            "file_name": item["file_name"],
            "stored_hash": item["stored_hash"],
            "current_hash": current_hash,
            "verification_status": "TAMPERED",
            "message": "INTEGRITY VIOLATION: Current SHA-256 hash does not match recorded catalog hash. File bytes have been modified.",
            "timestamp": now_iso,
        }


@app.get("/api/threat-intel/lookup")
def threat_intel_lookup(query: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    q = query.strip()
    matched_alerts = db.scalars(
        select(Alert).where(
            (Alert.source_ip.contains(q)) |
            (Alert.destination_ip.contains(q)) |
            (Alert.incident_id.contains(q)) |
            (Alert.attack_type.contains(q)) |
            (Alert.target.contains(q))
        )
    ).all()

    mitre_database = {
        "Brute Force": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
            "mitigation": "M1036 - Account Use Policies, M1032 - Multi-factor Authentication",
        },
        "Port Scan": {
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
            "mitigation": "M1037 - Filter Network Traffic, M1030 - Network Segmentation",
        },
        "DDoS": {
            "tactic": "Impact",
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "description": "Adversaries may perform Network Denial of Service attacks to degrade or block resource availability.",
            "mitigation": "M1037 - Filter Network Traffic, Rate limiting and upstream scrubbing",
        },
        "Infiltration": {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "description": "Adversaries may exploit vulnerabilities in Internet-facing applications or web servers.",
            "mitigation": "M1051 - Update Software, M1050 - Exploit Protection",
        },
        "Probe": {
            "tactic": "Reconnaissance",
            "technique_id": "T1595",
            "technique_name": "Active Scanning",
            "description": "Adversaries may execute active reconnaissance scans to gather information on network services and vulnerabilities.",
            "mitigation": "M1037 - Filter Network Traffic, IP rate limiting",
        },
    }

    associated_types = set()
    for a in matched_alerts:
        if a.attack_type:
            associated_types.add(a.attack_type)

    for atype in mitre_database:
        if atype.lower() in q.lower():
            associated_types.add(atype)

    if not associated_types:
        associated_types.add("Port Scan")

    correlated_techniques = []
    for atype in associated_types:
        info = mitre_database.get(atype, {
            "tactic": "Execution",
            "technique_id": "T1204",
            "technique_name": f"{atype} Behavioral Pattern",
            "description": f"Observed network traffic pattern associated with {atype}.",
            "mitigation": "Monitor anomalous network behavior and apply ingress access control lists.",
        })
        correlated_techniques.append({
            "attack_type": atype,
            "tactic": info["tactic"],
            "technique_id": info["technique_id"],
            "technique_name": info["technique_name"],
            "description": info["description"],
            "mitigation": info["mitigation"],
        })

    has_critical = any(a.severity == "CRITICAL" for a in matched_alerts)
    has_high = any(a.severity == "HIGH" for a in matched_alerts)
    if has_critical:
        rep_score = 92
        rep_level = "MALICIOUS"
    elif has_high or len(matched_alerts) > 1:
        rep_score = 78
        rep_level = "SUSPICIOUS"
    elif len(matched_alerts) == 1:
        rep_score = 50
        rep_level = "EVALUATING"
    else:
        rep_score = 15
        rep_level = "NEUTRAL"

    return {
        "query": q,
        "matched_incidents_count": len(matched_alerts),
        "reputation_score": rep_score,
        "reputation_level": rep_level,
        "mitre_techniques": correlated_techniques,
        "matched_incidents": [
            {
                "incident_id": a.incident_id,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "source_ip": a.source_ip,
                "target": a.target,
                "status": a.status,
                "timestamp": a.created_at,
            }
            for a in matched_alerts[:10]
        ],
        "intel_source": "CyberSentinel-X Local Threat Matrix & MITRE ATT&CK Knowledge Base",
    }



@app.get("/api/alerts", response_model=list[AlertResponse])
def get_alerts(db: Session = Depends(get_db)):
    statement = select(Alert).order_by(Alert.id.desc())
    return db.scalars(statement).all()


@app.get("/api/alerts/{incident_id}", response_model=AlertResponse)
def get_alert(incident_id: str, db: Session = Depends(get_db)):
    alert = db.scalar(
        select(Alert).where(Alert.incident_id == incident_id)
    )

    if alert is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return alert


@app.post("/api/alerts", response_model=AlertResponse, status_code=201)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
):
    existing = db.scalar(
        select(Alert).where(Alert.incident_id == payload.incident_id)
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Incident ID already exists",
        )

    alert = Alert(**payload.model_dump())
    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


@app.patch("/api/alerts/{incident_id}/status", response_model=AlertResponse)
def update_alert_status(
    incident_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    allowed_statuses = {
        "Open",
        "Investigating",
        "Resolved",
    }

    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail=f"Status must be one of: {sorted(allowed_statuses)}",
        )

    alert = db.scalar(
        select(Alert).where(Alert.incident_id == incident_id)
    )

    if alert is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    alert.status = payload.status
    db.commit()
    db.refresh(alert)

    return alert


@app.post("/api/alerts/clear")
def clear_all_alerts(db: Session = Depends(get_db)):
    """
    Clears all stored alerts from the SQLite database so the dashboard starts fresh.
    """
    count = db.query(Alert).delete()
    db.commit()
    return {"status": "cleared", "deleted_count": count}


@app.post("/api/alerts/seed-demo")
def seed_demo_alerts_endpoint(db: Session = Depends(get_db)):
    """
    Restores baseline demo incidents into the SQLite database.
    """
    seed_demo_data()
    total = db.scalar(select(func.count()).select_from(Alert)) or 0
    return {"status": "seeded", "total_alerts": total}


@app.post("/api/predict")
def predict_network_traffic(
    payload: TrafficPredictionRequest,
):
    try:
        return predict_traffic(payload.features)
    except FileNotFoundError as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error
    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Prediction failed: {error}",
        ) from error


# ============================================================================
# Authorized Network Traffic Monitoring Endpoints
# ============================================================================

@app.get("/api/monitoring/status")
def get_monitoring_status():
    """
    Returns current monitoring state, active source, processed flow counts,
    and any reported errors.
    """
    return monitoring_manager.get_status()


@app.get("/api/monitoring/metrics")
def get_monitoring_metrics():
    """
    Returns telemetry ingestion counters, prediction distribution,
    and the stream of recent classified flows.
    """
    return monitoring_manager.get_metrics()


@app.get("/api/monitoring/interfaces")
def get_monitoring_interfaces():
    """
    Discovers available host network interfaces and verifies Npcap/libpcap driver status.
    """
    return {
        "pcap_available": is_pcap_available(),
        "interfaces": get_available_interfaces(),
    }


@app.post("/api/monitoring/start")
def start_monitoring_session(payload: MonitoringStartRequest | None = None):
    """
    Explicitly starts an authorized live network capture session on the requested interface.
    """
    try:
        interface = payload.interface if payload else None
        bpf_filter = payload.bpf_filter if payload else None
        mode = payload.mode if (payload and payload.mode) else "real"
        return monitoring_manager.start_monitoring(interface=interface, bpf_filter=bpf_filter, mode=mode)
    except (RuntimeError, ValueError) as r_err:
        raise HTTPException(status_code=400, detail=str(r_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {exc}")


@app.post("/api/monitoring/stop")
def stop_monitoring_session():
    """
    Cleanly halts active live packet sniffing without leaving orphan processes.
    """
    return monitoring_manager.stop_monitoring()


@app.get("/api/monitoring/sample-pcap")
def get_sample_pcap():
    """
    Returns an authorized sample PCAP byte stream containing HTTP, DNS, and probe traffic
    for pipeline verification and testing.
    """
    pcap_data = generate_sample_pcap_bytes()
    return Response(
        content=pcap_data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": 'attachment; filename="cybersentinel_authorized_sample.pcap"'},
    )


class LocalPcapIngestRequest(BaseModel):
    file_path: str
    max_packets: Optional[int] = None
    flow_timeout: float = 30.0


@app.post("/api/monitoring/pcap")
async def ingest_pcap_file(file: UploadFile = File(...)):
    """
    Ingests an authorized PCAP / PCAPNG packet capture file, extracts 70-feature flows,
    classifies them using Random Forest, and persists ATTACK alerts in the database.
    Streams upload directly to disk in chunks to safely support massive 12+ GB files.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing file name")

    # Stream chunks directly to disk without buffering multi-gigabytes into RAM
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
        try:
            while chunk := await file.read(4 * 1024 * 1024):  # 4MB streaming chunks
                tmp.write(chunk)
        except Exception as read_exc:
            tmp.close()
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise HTTPException(status_code=400, detail=f"Failed to stream upload: {read_exc}")

    try:
        return monitoring_manager.ingest_pcap_file_path(tmp_path, filename=file.filename)
    except PcapValidationError as v_err:
        raise HTTPException(status_code=422, detail=str(v_err))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"PCAP ingestion failed: {exc}")
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


@app.post("/api/monitoring/pcap/local")
def ingest_local_pcap_file(req: LocalPcapIngestRequest):
    """
    Directly streams and analyzes an authorized PCAP/PCAPNG file from the local filesystem.
    Ideal for massive captures (e.g. 12 GB raw dataset captures) with zero upload latency.
    """
    clean_path = req.file_path.strip().strip('"').strip("'")
    target_path = Path(clean_path)
    if not target_path.exists():
        raise HTTPException(status_code=404, detail=f"Local PCAP file not found: '{clean_path}'")

    try:
        return monitoring_manager.ingest_pcap_file_path(
            filepath=target_path,
            filename=target_path.name,
            max_packets=req.max_packets,
            flow_timeout=req.flow_timeout,
        )
    except PcapValidationError as v_err:
        raise HTTPException(status_code=422, detail=str(v_err))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Local PCAP ingestion failed: {exc}")


@app.get("/api/monitoring/pcap/progress")
def get_pcap_ingestion_progress():
    """
    Returns real-time packet processing, flow extraction, and threat classification telemetry.
    """
    return monitoring_manager.get_pcap_progress()


@app.post("/api/monitoring/pcap/stop")
def stop_pcap_ingestion():
    """
    Stops active PCAP stream ingestion immediately.
    """
    return monitoring_manager.stop_pcap_ingestion()


@app.post("/api/monitoring/reset")
def reset_monitoring_telemetry():
    """
    Resets all flow counters, packet counters, benign/attack tallies, and
    inspection buffers back to 0. Records milestone in session history.
    """
    return monitoring_manager.reset_counters()


@app.get("/api/monitoring/history")
def get_monitoring_history():
    """
    Returns the comprehensive ledger of past capture sessions, PCAP uploads,
    and telemetry reset milestones.
    """
    return {
        "history": monitoring_manager.get_session_history(),
    }


@app.post("/api/monitoring/history/clear")
def clear_monitoring_history():
    """
    Clears the session history log.
    """
    return monitoring_manager.clear_session_history()


# ============================================================================
# RAG (Retrieval-Augmented Generation) & LangChain AI Copilot Endpoints
# ============================================================================

class IncidentInvestigateRequest(BaseModel):
    incident_id: str
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    confidence: Optional[float] = None
    reason: Optional[str] = None


@app.post("/api/ai/investigate", response_model=AIInvestigationResponse)
def api_investigate_incident(req: IncidentInvestigateRequest, db: Session = Depends(get_db)):
    """
    Performs real-time RAG investigation over an incident using MITRE ATT&CK techniques,
    NIST SP 800-61 playbooks, and LangChain/deterministic reasoning.
    """
    alert_record = db.scalar(select(Alert).where(Alert.incident_id == req.incident_id))
    
    alert_dict = {
        "incident_id": req.incident_id,
        "attack_type": req.attack_type or (alert_record.attack_type if alert_record else "Network Anomaly"),
        "source_ip": req.source_ip or (alert_record.source_ip if alert_record else "0.0.0.0"),
        "destination_ip": req.destination_ip or (alert_record.destination_ip if alert_record else "10.0.0.1"),
        "confidence": req.confidence or (alert_record.confidence if alert_record else 90.0),
        "reason": req.reason or (alert_record.reason if alert_record else "Anomalous traffic detected by ML engine"),
    }
    
    return investigate_incident_rag(alert_dict)


@app.post("/api/ai/copilot-chat")
def api_copilot_chat(query_req: AICopilotQuery, db: Session = Depends(get_db)):
    """
    Interactive SOC Analyst AI Copilot grounded in MITRE ATT&CK knowledge base.
    Answers technical questions, writes firewall rules, and explains packet signatures.
    """
    incident_data = None
    if query_req.incident_id:
        alert = db.scalar(select(Alert).where(Alert.incident_id == query_req.incident_id))
        if alert:
            incident_data = {
                "incident_id": alert.incident_id,
                "attack_type": alert.attack_type,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "confidence": alert.confidence,
                "reason": alert.reason,
            }
        elif query_req.context:
            incident_data = query_req.context

    return chat_with_copilot_rag(query_req.query, incident_data)


@app.get("/api/ai/knowledge-stats")
def api_knowledge_stats():
    """
    Returns vector index metadata, indexed MITRE ATT&CK techniques, and active LLM provider.
    """
    provider = "LangChain (Live LLM)" if (os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")) else "Deterministic SOC RAG Engine (Zero API Cost)"
    return {
        "indexed_techniques_count": len(CYBER_KNOWLEDGE_BASE),
        "techniques": [
            {
                "id": t["technique_id"],
                "name": t["technique_name"],
                "tactics": t["tactics"],
            }
            for t in CYBER_KNOWLEDGE_BASE
        ],
        "active_provider": provider,
        "rag_status": "ONLINE",
        "supported_providers": ["LangChain", "OpenAI", "Google Gemini", "Local Semantic Vector RAG"],
    }


