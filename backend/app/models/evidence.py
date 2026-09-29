"""
Evidence Model - Evidence collection for findings
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class EvidenceType(str, enum.Enum):
    SOURCE_CODE = "source_code"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    LOG = "log"
    REPRODUCTION = "reproduction"
    CONFIGURATION = "configuration"


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = Column(String(20), unique=True, nullable=False)  # e.g., EVID-0001
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)

    evidence_type = Column(String(50), nullable=False)
    title = Column(String(500), nullable=True)
    description = Column(Text, nullable=True)
    content = Column(Text, nullable=True)  # text content or base64 for binary

    # HTTP specific
    request_method = Column(String(10), nullable=True)
    request_url = Column(String(1000), nullable=True)
    request_headers = Column(JSON, nullable=True)
    request_body = Column(Text, nullable=True)
    response_status = Column(String(10), nullable=True)
    response_headers = Column(JSON, nullable=True)
    response_body = Column(Text, nullable=True)

    # Source code specific
    file_path = Column(String(500), nullable=True)
    line_start = Column(String(10), nullable=True)
    line_end = Column(String(10), nullable=True)
    code_snippet = Column(Text, nullable=True)

    # File evidence
    file_name = Column(String(255), nullable=True)
    file_size = Column(String(20), nullable=True)
    mime_type = Column(String(100), nullable=True)

    # Metadata
    captured_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    finding = relationship("Finding", back_populates="evidence_items")
