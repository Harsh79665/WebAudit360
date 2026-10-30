"""WebAudit 360 — Base Audit Engine Contract
Author: Harsh Patel
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditCategory(str, Enum):
    PERFORMANCE = "PERFORMANCE"
    SEO = "SEO"
    ACCESSIBILITY = "ACCESSIBILITY"
    SECURITY_PASSIVE = "SECURITY_PASSIVE"
    SECURITY_ACTIVE = "SECURITY_ACTIVE"
    RESPONSIVE = "RESPONSIVE"
    TECHNICAL_HEALTH = "TECHNICAL_HEALTH"
    TECHNOLOGY = "TECHNOLOGY"
    VISUAL = "VISUAL"
    API_HEALTH = "API_HEALTH"
    THIRD_PARTY = "THIRD_PARTY"
    DOMAIN = "DOMAIN"


class EngineStatus(str, Enum):
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"


class FindingDraft(BaseModel):
    category: AuditCategory
    rule_id: str
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 1.0
    title: str
    description: str
    recommendation: Optional[str] = None
    selector: Optional[str] = None
    evidence_snippet: Optional[str] = None
    raw_details: Dict[str, Any] = Field(default_factory=dict)


class EngineResult(BaseModel):
    category: AuditCategory
    engine_name: str
    engine_version: str
    status: EngineStatus
    score: Optional[float] = None  # 0.0 to 100.0, or None (N/A)
    findings: List[FindingDraft] = Field(default_factory=list)
    raw_evidence: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)
    execution_time_ms: int = 0
    error: Optional[str] = None


class BaseAuditEngine(ABC):
    """Abstract base class that all WebAudit 360 auditing engines must implement."""

    engine_name: str = "BaseEngine"
    engine_version: str = "1.0.0"
    category: AuditCategory = AuditCategory.PERFORMANCE

    @abstractmethod
    async def execute(
        self,
        target_url: str,
        config: Dict[str, Any],
        **kwargs
    ) -> EngineResult:
        """
        Executes the audit against the validated target URL.
        Must return a structured EngineResult instance.
        """
        pass
