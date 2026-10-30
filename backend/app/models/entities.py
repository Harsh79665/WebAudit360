"""WebAudit 360 — SQLAlchemy 2 Database Entities
Author: Harsh Patel
"""

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship
from backend.app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class AuditStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    RUNNING = "RUNNING"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanMode(str, enum.Enum):
    SINGLE_PAGE = "SINGLE_PAGE"
    FULL_SITE = "FULL_SITE"


class DeviceProfile(str, enum.Enum):
    MOBILE = "MOBILE"
    DESKTOP = "DESKTOP"
    BOTH = "BOTH"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "DNS_TXT"
    HTTP_FILE = "HTTP_FILE"


class VerificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.DEVELOPER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")
    audits = relationship("Audit", back_populates="user", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), index=True, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    owner = relationship("User", back_populates="projects")
    audits = relationship("Audit", back_populates="project", cascade="all, delete-orphan")
    authorizations = relationship("DomainAuthorization", back_populates="project", cascade="all, delete-orphan")
    monitoring_schedules = relationship("MonitoringSchedule", back_populates="project", cascade="all, delete-orphan")


class DomainAuthorization(Base):
    __tablename__ = "domain_authorizations"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    token = Column(String(128), nullable=False)
    verification_method = Column(Enum(VerificationMethod), default=VerificationMethod.DNS_TXT, nullable=False)
    status = Column(Enum(VerificationStatus), default=VerificationStatus.PENDING, nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    project = relationship("Project", back_populates="authorizations")


class Audit(Base):
    __tablename__ = "audits"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target_url = Column(String(2048), nullable=False)
    scan_mode = Column(Enum(ScanMode), default=ScanMode.SINGLE_PAGE, nullable=False)
    device_profile = Column(Enum(DeviceProfile), default=DeviceProfile.BOTH, nullable=False)
    status = Column(Enum(AuditStatus), default=AuditStatus.QUEUED, nullable=False, index=True)
    
    # Versioned Scores (0.0 to 100.0 or None)
    overall_score = Column(Float, nullable=True)
    score_performance = Column(Float, nullable=True)
    score_seo = Column(Float, nullable=True)
    score_accessibility = Column(Float, nullable=True)
    score_security = Column(Float, nullable=True)
    score_technical = Column(Float, nullable=True)
    scoring_version = Column(String(32), default="1.0.0", nullable=False)

    pages_discovered = Column(Integer, default=0, nullable=False)
    pages_scanned = Column(Integer, default=0, nullable=False)
    pages_failed = Column(Integer, default=0, nullable=False)
    execution_time_ms = Column(Integer, default=0, nullable=False)

    selected_modules = Column(JSON, default=list, nullable=False)
    config = Column(JSON, default=dict, nullable=False)
    raw_results = Column(JSON, default=dict, nullable=False)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="audits")
    project = relationship("Project", back_populates="audits")
    pages = relationship("AuditPage", back_populates="audit", cascade="all, delete-orphan")
    findings = relationship("AuditFinding", back_populates="audit", cascade="all, delete-orphan")


class AuditPage(Base):
    __tablename__ = "audit_pages"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("audits.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    path = Column(String(2048), nullable=False)
    status_code = Column(Integer, nullable=True)
    crawl_depth = Column(Integer, default=0, nullable=False)
    response_time_ms = Column(Integer, nullable=True)
    content_type = Column(String(128), nullable=True)
    is_orphan = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    audit = relationship("Audit", back_populates="pages")
    findings = relationship("AuditFinding", back_populates="page", cascade="all, delete-orphan")


class AuditFinding(Base):
    __tablename__ = "audit_findings"

    id = Column(Integer, primary_key=True, index=True)
    audit_id = Column(Integer, ForeignKey("audits.id"), nullable=False, index=True)
    page_id = Column(Integer, ForeignKey("audit_pages.id"), nullable=True, index=True)
    category = Column(String(64), index=True, nullable=False)  # PERFORMANCE, SEO, ACCESSIBILITY, SECURITY, RESPONSIVE, etc.
    rule_id = Column(String(128), index=True, nullable=False)
    severity = Column(Enum(FindingSeverity), default=FindingSeverity.INFO, nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    selector = Column(String(1024), nullable=True)
    evidence_snippet = Column(Text, nullable=True)
    raw_details = Column(JSON, default=dict, nullable=False)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    audit = relationship("Audit", back_populates="findings")
    page = relationship("AuditPage", back_populates="findings")
    history = relationship("FindingHistory", back_populates="finding", cascade="all, delete-orphan")


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("audit_findings.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    old_status = Column(String(64), nullable=True)
    new_status = Column(String(64), nullable=False)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    finding = relationship("AuditFinding", back_populates="history")


class MonitoringSchedule(Base):
    __tablename__ = "monitoring_schedules"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    interval_days = Column(Integer, default=7, nullable=False)  # 1 = Daily, 7 = Weekly, 30 = Monthly
    is_active = Column(Boolean, default=True, nullable=False)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    alert_on_regression = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    project = relationship("Project", back_populates="monitoring_schedules")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    label = Column(String(255), nullable=False)
    key_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA-256
    prefix = Column(String(16), nullable=False)  # e.g. "w360_live_..."
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Webhook(Base):
    __tablename__ = "webhooks"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    url = Column(String(2048), nullable=False)
    secret_hash = Column(String(64), nullable=False)
    events = Column(JSON, default=list, nullable=False)  # e.g. ["audit.completed", "regression.detected"]
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
