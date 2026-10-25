from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AlertCreate(BaseModel):
    incident_id: str = Field(min_length=3, max_length=50)
    attack_type: str = Field(min_length=2, max_length=100)
    source_ip: str = Field(min_length=3, max_length=64)
    destination_ip: str = Field(min_length=3, max_length=64)
    target: str = Field(min_length=1, max_length=100)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    confidence: float = Field(ge=0.0, le=100.0)
    status: Literal["Open", "Investigating", "Resolved"] = "Open"
    reason: str = Field(min_length=3, max_length=2000)
    created_at: str

    @field_validator("incident_id")
    @classmethod
    def validate_incident_id(cls, v: str) -> str:
        clean = v.strip()
        if clean.lower() == "string" or len(clean) < 3:
            raise ValueError("incident_id cannot be a literal placeholder 'string'")
        if not re.match(r"^[A-Za-z0-9_\-\.:]+$", clean):
            raise ValueError("incident_id contains invalid characters")
        return clean

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_or_host(cls, v: str) -> str:
        clean = v.strip()
        if clean.lower() == "string":
            raise ValueError("IP address cannot be placeholder 'string'")
        return clean

    @field_validator("attack_type", "target", "reason")
    @classmethod
    def validate_non_placeholder_text(cls, v: str) -> str:
        clean = v.strip()
        if clean.lower() == "string":
            raise ValueError("Field cannot be literal placeholder 'string'")
        return clean

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, v: str) -> str:
        clean = v.strip()
        if clean.lower() == "string":
            raise ValueError("created_at cannot be literal 'string'")
        try:
            # Validate ISO timestamp or date
            datetime.fromisoformat(clean.replace("Z", "+00:00"))
        except Exception:
            # Allow clean fallback format if already valid
            if len(clean) < 8:
                raise ValueError("created_at must be an ISO format timestamp string")
        return clean


class AlertResponse(AlertCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: Literal["Open", "Investigating", "Resolved"]


class EvidenceItemSchema(BaseModel):
    id: str
    file_name: str
    incident_id: str
    stored_hash: str
    current_hash: Optional[str] = None
    file_size: str
    blockchain_status: Literal["Recorded", "Pending"]
    verification_status: Literal["VERIFIED", "TAMPERED", "MISSING", "ERROR"]
    timestamp: str
    recorded_block: Optional[str] = None


class EvidenceVerifyRequest(BaseModel):
    evidence_id: str


class EvidenceVerifyResponse(BaseModel):
    evidence_id: str
    file_name: str
    stored_hash: str
    current_hash: str
    verification_status: Literal["VERIFIED", "TAMPERED", "MISSING", "ERROR"]
    message: str
    timestamp: str


class AnalyticsSummaryResponse(BaseModel):
    total_alerts: int
    attack_distribution: List[Dict[str, Any]]
    risk_distribution: List[Dict[str, Any]]
    weekly_activity: List[Dict[str, Any]]
    top_source_ips: List[Dict[str, Any]]
    top_targets: List[Dict[str, Any]]
    status_pipeline: Dict[str, int]


class RiskFactorSchema(BaseModel):
    name: str
    level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    score: float


class IncidentRiskSchema(BaseModel):
    incident_id: str
    attack_type: str
    severity: str
    confidence: float
    calculated_risk_score: float
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    factors: List[RiskFactorSchema]
    explanation: str


class RiskSummaryResponse(BaseModel):
    overall_score: float
    overall_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    scoring_formula: str
    incidents: List[IncidentRiskSchema]
