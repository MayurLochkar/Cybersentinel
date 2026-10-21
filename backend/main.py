# Entry point for backend application

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from models import Alert
from schemas import AlertCreate, AlertResponse, AlertStatusUpdate
from pydantic import BaseModel, Field
from ml.predict import predict_traffic


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
    yield


class TrafficPredictionRequest(BaseModel):
    features: dict[str, float] = Field(
        ...,
        description="Numeric CICIDS2017 network-flow features",
    )


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

    return {
        "total_alerts": total,
        "critical": critical,
        "high_risk": high_risk,
        "active_investigations": active,
        "verified_evidence": 0,
        "data_source": "SQLite demo records",
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
