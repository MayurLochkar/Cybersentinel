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
