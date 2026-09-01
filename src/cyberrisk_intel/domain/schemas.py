from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from cyberrisk_intel.domain.enums import (
    Confidence,
    EntityType,
    PolicyDocumentType,
    ReviewStatus,
    Severity,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SourceInput(StrictModel):
    name: str = Field(min_length=2, max_length=300)
    url: HttpUrl
    publisher: str = Field(min_length=2, max_length=300)
    source_type: str = Field(min_length=2, max_length=80)
    region: str = "Global"
    reliability: Confidence = Confidence.MEDIUM
    license_name: str | None = None


class PolicyInput(StrictModel):
    external_id: str | None = Field(default=None, max_length=120)
    title: str = Field(min_length=2, max_length=500)
    issuer: str = Field(min_length=2, max_length=300)
    document_type: PolicyDocumentType = PolicyDocumentType.OTHER
    jurisdiction: str = "CN"
    published_date: date | None = None
    effective_date: date | None = None
    status: ReviewStatus = ReviewStatus.PENDING
    summary: str = Field(min_length=10)
    source: SourceInput
    topics: list[str] = Field(default_factory=list)
    clauses: list[dict[str, Any]] = Field(default_factory=list)


class EventInput(StrictModel):
    external_id: str | None = Field(default=None, max_length=120)
    title: str = Field(min_length=2, max_length=500)
    title_zh: str | None = Field(default=None, max_length=500)
    summary: str = Field(min_length=10)
    summary_zh: str | None = None
    incident_date: date
    disclosed_date: date | None = None
    region: str = "Global"
    organization: str | None = Field(default=None, max_length=300)
    organization_type: str | None = Field(default=None, max_length=120)
    industry: str
    threat_patterns: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    affected_data: list[str] = Field(default_factory=list)
    root_cause: str | None = None
    impact: str | None = None
    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.MEDIUM
    status: ReviewStatus = ReviewStatus.PENDING
    cve_ids: list[str] = Field(default_factory=list)
    attack_ids: list[str] = Field(default_factory=list)
    risk_themes: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    sources: list[SourceInput] = Field(min_length=1)

    @field_validator("cve_ids")
    @classmethod
    def validate_cves(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item.startswith("CVE-"):
                raise ValueError(f"Invalid CVE identifier: {item}")
        return value


class VulnerabilityInput(StrictModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    description: str = Field(min_length=5)
    published_date: date | None = None
    updated_date: date | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_severity: Severity = Severity.UNKNOWN
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    is_kev: bool = False
    known_ransomware_use: bool = False
    required_action: str | None = None
    due_date: date | None = None
    source_url: HttpUrl | None = None


class AttackTechniqueInput(StrictModel):
    attack_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str
    description: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    version: str | None = None
    revoked: bool = False
    source_url: HttpUrl | None = None


class RelationshipInput(StrictModel):
    subject_type: EntityType
    subject_id: str
    predicate: str = Field(min_length=2, max_length=80)
    object_type: EntityType
    object_id: str
    evidence_excerpt: str = Field(min_length=3)
    source_id: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    created_by: str = "human"
    review_status: ReviewStatus = ReviewStatus.PENDING
