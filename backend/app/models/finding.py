"""
Finding Model - Security vulnerability findings
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String(20), unique=True, nullable=False)  # e.g., FIND-0001
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True)

    # Classification
    title = Column(String(500), nullable=False)
    severity = Column(String(20), nullable=False, default=Severity.INFORMATIONAL)
    confidence = Column(String(20), nullable=False, default=Confidence.POTENTIAL)
    status = Column(String(20), nullable=False, default=FindingStatus.OPEN)
    category = Column(String(100), nullable=True)

    # CVSS
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    cvss_details = Column(JSON, nullable=True)

    # CWE
    cwe_id = Column(String(20), nullable=True)
    cwe_name = Column(String(200), nullable=True)

    # Affected component
    affected_component = Column(String(500), nullable=True)
    affected_file = Column(String(500), nullable=True)
    affected_line = Column(String(50), nullable=True)
    affected_endpoint = Column(String(500), nullable=True)

    # Details
    description = Column(Text, nullable=True)
    technical_details = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    rule_id = Column(String(100), nullable=True)

    # Reproduction
    steps_to_reproduce = Column(Text, nullable=True)
    poc = Column(Text, nullable=True)

    # Impact & Remediation
    impact = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    retest_procedure = Column(Text, nullable=True)

    # Metadata
    scanner_source = Column(String(100), nullable=True)  # which scanner found it
    is_ai_assisted = Column(String(10), default="false")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    project = relationship("Project", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    evidence_items = relationship("Evidence", back_populates="finding", cascade="all, delete-orphan")
