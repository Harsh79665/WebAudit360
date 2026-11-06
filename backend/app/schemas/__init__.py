"""WebAudit 360 — Pydantic Validation & API Schemas
Author: Harsh Patel
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from backend.app.models.entities import (
    AuditStatus,
    DeviceProfile,
    FindingSeverity,
    FindingStatus,
    ScanMode,
    UserRole,
    VerificationMethod,
    VerificationStatus,
)


# --- Common & Pagination ---
class StatusResponse(BaseModel):
    success: bool = True
    message: str


class PaginationParams(BaseModel):
    skip: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


# --- Auth & User ---
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime


class AuthSuccessResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


# --- Projects ---
class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    domain: Optional[str] = None
    description: Optional[str] = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    name: str
    domain: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ProjectListResponse(BaseModel):
    items: List[ProjectResponse]
    total: int


# --- Domain Authorization ---
class DomainAuthCreate(BaseModel):
    project_id: int
    domain: str
    verification_method: VerificationMethod = VerificationMethod.DNS_TXT


class DomainAuthResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    domain: str
    token: str
    verification_method: VerificationMethod
    status: VerificationStatus
    verified_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime


# --- Audits ---
class AuditCreate(BaseModel):
    target_url: str
    project_id: Optional[int] = None
    scan_mode: ScanMode = ScanMode.SINGLE_PAGE
    device_profile: DeviceProfile = DeviceProfile.BOTH
    selected_modules: List[str] = Field(default_factory=lambda: [
        "PERFORMANCE", "SEO", "ACCESSIBILITY", "SECURITY_PASSIVE",
        "RESPONSIVE", "TECHNICAL_HEALTH", "TECHNOLOGY", "THIRD_PARTY",
        "VISUAL"
    ])
    max_pages: Optional[int] = 50
    max_depth: Optional[int] = 3
    concurrency: Optional[int] = 2


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: Optional[int] = None
    user_id: Optional[int] = None
    target_url: str
    scan_mode: ScanMode
    device_profile: DeviceProfile
    status: AuditStatus

    overall_score: Optional[float] = None
    score_performance: Optional[float] = None
    score_seo: Optional[float] = None
    score_accessibility: Optional[float] = None
    score_security: Optional[float] = None
    score_technical: Optional[float] = None
    scoring_version: str

    pages_discovered: int
    pages_scanned: int
    pages_failed: int
    execution_time_ms: int

    selected_modules: List[str]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class AuditListResponse(BaseModel):
    items: List[AuditResponse]
    total: int


# --- Findings ---
class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    audit_id: int
    page_id: Optional[int] = None
    category: str
    rule_id: str
    severity: FindingSeverity
    confidence: float
    title: str
    description: str
    recommendation: Optional[str] = None
    selector: Optional[str] = None
    evidence_snippet: Optional[str] = None
    raw_details: Dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus
    created_at: datetime
    updated_at: datetime


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int


class AuditPageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    audit_id: int
    url: str
    path: str
    status_code: Optional[int] = None
    crawl_depth: int = 0
    response_time_ms: Optional[int] = None
    content_type: Optional[str] = None
    is_orphan: bool = False
    created_at: datetime


class AuditDetailResponse(AuditResponse):
    raw_results: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingResponse] = Field(default_factory=list)
    pages: List[AuditPageResponse] = Field(default_factory=list)
    category_scores: Dict[str, Optional[float]] = Field(default_factory=dict)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    reason: Optional[str] = None


# --- Monitoring Schedules ---
class ScheduleCreate(BaseModel):
    project_id: int
    target_url: str
    interval_days: int = Field(default=7, ge=1, le=90)
    alert_on_regression: bool = True


class ScheduleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    target_url: str
    interval_days: int
    is_active: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    alert_on_regression: bool
    created_at: datetime


# --- Visual Regression ---
class ViewportVisualDiff(BaseModel):
    width: int
    height: int
    current_url: Optional[str] = None
    baseline_url: Optional[str] = None
    diff_url: Optional[str] = None
    mismatch_percentage: float = 0.0
    diff_pixels: int = 0
    total_pixels: int = 0
    has_baseline: bool = False


class VisualRegressionResponse(BaseModel):
    audit_id: int
    target_url: str
    baseline_audit_id: Optional[int] = None
    baseline_established: bool = False
    score: Optional[float] = None
    overall_mismatch_percentage: float = 0.0
    viewports: Dict[str, ViewportVisualDiff] = Field(default_factory=dict)


# --- Integrations (API Keys & Webhooks) ---
class ApiKeyCreate(BaseModel):
    label: str = Field(min_length=1, max_length=255, description="Descriptive label for this API key")
    expires_in_days: Optional[int] = Field(default=365, ge=1, le=3650, description="Validity window in days (default 365, null for non-expiring)")


class ApiKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    label: str
    prefix: str
    is_active: bool
    expires_at: Optional[datetime] = None
    created_at: datetime


class ApiKeyCreatedResponse(ApiKeyResponse):
    api_key: str = Field(description="Plaintext secret API key returned only once upon creation")


class WebhookCreate(BaseModel):
    project_id: Optional[int] = Field(default=None, description="Project ID to bind webhook to; if omitted, bound to default project")
    url: str = Field(min_length=10, max_length=2048, description="Target destination URL for webhook events")
    events: List[str] = Field(
        default_factory=lambda: ["audit.completed", "regression.detected"],
        description="Event types that trigger this webhook"
    )


class WebhookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    url: str
    events: List[str]
    is_active: bool
    created_at: datetime


class WebhookCreatedResponse(WebhookResponse):
    secret: str = Field(description="HMAC secret key returned only once upon creation for signature verification")


class WebhookTestResponse(BaseModel):
    success: bool
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    message: str


# --- Team Management ---
class TeamMemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool
    created_at: datetime
    initial_password: Optional[str] = Field(
        default=None,
        description="Populated only upon initial member invitation generation."
    )


class TeamMemberListResponse(BaseModel):
    items: List[TeamMemberResponse]
    total: int


class TeamInviteRequest(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = Field(
        default=UserRole.DEVELOPER,
        description="Initial role assignment (OWNER, ADMIN, DEVELOPER, VIEWER)."
    )


class TeamRoleUpdateRequest(BaseModel):
    role: UserRole = Field(
        ...,
        description="New role to assign to the workspace member."
    )

