from sqlalchemy import Column, Float, Integer, String, Text

from database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(30), unique=True, index=True, nullable=False)

    attack_type = Column(String(100), nullable=False)
    source_ip = Column(String(50), nullable=False)
    destination_ip = Column(String(50), nullable=False)
    target = Column(String(100), nullable=False)

    severity = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    status = Column(String(30), default="Open", nullable=False)

    reason = Column(Text, nullable=False)
    created_at = Column(String(40), nullable=False)


class InvestigationReport(Base):
    __tablename__ = "investigation_reports"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(50), index=True, nullable=False)
    status = Column(String(30), default="Completed", nullable=False)

    executive_summary = Column(Text, nullable=False)
    attack_type = Column(String(100), nullable=False)
    technique_id = Column(String(30), nullable=True)
    technique_name = Column(String(100), nullable=True)
    tactics_json = Column(Text, nullable=True)

    confidence = Column(Float, nullable=False)
    source_ip = Column(String(50), nullable=False)
    destination_ip = Column(String(50), nullable=False)
    target = Column(String(100), nullable=True)

    forensic_hypothesis = Column(Text, nullable=False)
    containment_playbook_json = Column(Text, nullable=False)
    snort_defense_rule = Column(Text, nullable=False)
    rag_citations_json = Column(Text, nullable=False)
    retrieved_context_json = Column(Text, nullable=False)

    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    evidence_integrity = Column(String(30), default="VERIFIED", nullable=False)
    evidence_hashes_json = Column(Text, nullable=True)
    recommendations_json = Column(Text, nullable=True)
    competing_hypotheses_json = Column(Text, nullable=True)
    structured_findings_json = Column(Text, nullable=True)

    model_provider = Column(String(100), nullable=False)
    execution_log_json = Column(Text, nullable=True)
    created_at = Column(String(40), nullable=False)
    updated_at = Column(String(40), nullable=False)

