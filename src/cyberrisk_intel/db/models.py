from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Source(Base, TimestampMixin):
    __tablename__ = "source"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    publisher: Mapped[str] = mapped_column(Text, nullable=False)
    source_type: Mapped[str] = mapped_column(Text, nullable=False)
    region: Mapped[str] = mapped_column(Text, nullable=False, default="Global")
    reliability: Mapped[str] = mapped_column(Text, nullable=False, default="medium")
    license_name: Mapped[str | None] = mapped_column(Text)


class RawDocument(Base, TimestampMixin):
    __tablename__ = "raw_document"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    source_id: Mapped[str] = mapped_column(ForeignKey("source.id"), nullable=False)
    original_url: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot_path: Mapped[str | None] = mapped_column(Text)
    parse_status: Mapped[str] = mapped_column(Text, default="pending")
    source: Mapped[Source] = relationship()

    __table_args__ = (UniqueConstraint("original_url", "content_hash"),)


class IngestionRun(Base):
    __tablename__ = "ingestion_run"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    adapter: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text, default="running")
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)


class ReviewRecord(Base):
    __tablename__ = "review_record"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[str] = mapped_column(Text, nullable=False)
    previous_status: Mapped[str | None] = mapped_column(Text)
    new_status: Mapped[str] = mapped_column(Text, nullable=False)
    change_summary: Mapped[str | None] = mapped_column(Text)
    comment: Mapped[str | None] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(Text, default="local-user")
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (Index("ix_review_entity", "entity_type", "entity_id"),)


class ExtractionCandidate(Base, TimestampMixin):
    __tablename__ = "extraction_candidate"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[str | None] = mapped_column(Text)
    field_name: Mapped[str] = mapped_column(Text, nullable=False)
    candidate_json: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(Text, default="medium")
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")


class Policy(Base, TimestampMixin):
    __tablename__ = "policy"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    external_id: Mapped[str | None] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    document_type: Mapped[str] = mapped_column(Text, default="other")
    jurisdiction: Mapped[str] = mapped_column(Text, default="CN")
    published_date: Mapped[date | None] = mapped_column(Date)
    effective_date: Mapped[date | None] = mapped_column(Date)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    topics_json: Mapped[str] = mapped_column(Text, default="[]")
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")
    source_id: Mapped[str] = mapped_column(ForeignKey("source.id"), nullable=False)
    source: Mapped[Source] = relationship()
    versions: Mapped[list[PolicyVersion]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyVersion(Base, TimestampMixin):
    __tablename__ = "policy_version"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policy.id"), nullable=False)
    version_label: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_text: Mapped[str] = mapped_column(Text, default="")
    valid_from: Mapped[date | None] = mapped_column(Date)
    policy: Mapped[Policy] = relationship(back_populates="versions")
    clauses: Mapped[list[PolicyClause]] = relationship(
        back_populates="version", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("policy_id", "content_hash"),)


class PolicyClause(Base):
    __tablename__ = "policy_clause"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    version_id: Mapped[str] = mapped_column(ForeignKey("policy_version.id"), nullable=False)
    clause_ref: Mapped[str] = mapped_column(Text, nullable=False)
    hierarchy_path: Mapped[str] = mapped_column(Text, default="")
    title: Mapped[str | None] = mapped_column(Text)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")
    version: Mapped[PolicyVersion] = relationship(back_populates="clauses")
    obligations: Mapped[list[PolicyObligation]] = relationship(
        back_populates="clause", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("version_id", "clause_ref"),)


class PolicyObligation(Base):
    __tablename__ = "policy_obligation"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    clause_id: Mapped[str] = mapped_column(ForeignKey("policy_clause.id"), nullable=False)
    actor: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    object_text: Mapped[str | None] = mapped_column(Text)
    condition_text: Mapped[str | None] = mapped_column(Text)
    evidence_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")
    clause: Mapped[PolicyClause] = relationship(back_populates="obligations")


class Industry(Base):
    __tablename__ = "industry"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class ThreatPattern(Base):
    __tablename__ = "threat_pattern"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)


class SecurityEvent(Base, TimestampMixin):
    __tablename__ = "security_event"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    external_id: Mapped[str | None] = mapped_column(Text, unique=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    title_zh: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    summary_zh: Mapped[str | None] = mapped_column(Text)
    incident_date: Mapped[date] = mapped_column(Date, nullable=False)
    discovered_date: Mapped[date | None] = mapped_column(Date)
    disclosed_date: Mapped[date | None] = mapped_column(Date)
    region: Mapped[str] = mapped_column(Text, default="Global")
    organization: Mapped[str | None] = mapped_column(Text)
    organization_type: Mapped[str | None] = mapped_column(Text)
    industry_id: Mapped[str | None] = mapped_column(ForeignKey("industry.id"))
    root_cause: Mapped[str | None] = mapped_column(Text)
    affected_assets_json: Mapped[str] = mapped_column(Text, default="[]")
    affected_data_json: Mapped[str] = mapped_column(Text, default="[]")
    impact: Mapped[str | None] = mapped_column(Text)
    source_severity: Mapped[str] = mapped_column(Text, default="unknown")
    normalized_severity: Mapped[str] = mapped_column(Text, default="unknown")
    confidence: Mapped[str] = mapped_column(Text, default="medium")
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")
    industry: Mapped[Industry | None] = relationship()

    __table_args__ = (Index("ix_event_incident_date", "incident_date"),)


class EventSource(Base):
    __tablename__ = "event_source"

    event_id: Mapped[str] = mapped_column(ForeignKey("security_event.id"), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("source.id"), primary_key=True)
    evidence_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerability"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    cve_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    published_date: Mapped[date | None] = mapped_column(Date)
    updated_date: Mapped[date | None] = mapped_column(Date)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_severity: Mapped[str] = mapped_column(Text, default="unknown")
    cwe_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    affected_products_json: Mapped[str] = mapped_column(Text, default="[]")
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False)
    required_action: Mapped[str | None] = mapped_column(Text)
    due_date: Mapped[date | None] = mapped_column(Date)
    source_url: Mapped[str | None] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(Text, default="published")


class AttackTactic(Base):
    __tablename__ = "attack_tactic"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    attack_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")


class AttackTechnique(Base, TimestampMixin):
    __tablename__ = "attack_technique"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    attack_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    tactics_json: Mapped[str] = mapped_column(Text, default="[]")
    platforms_json: Mapped[str] = mapped_column(Text, default="[]")
    version: Mapped[str | None] = mapped_column(Text)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(Text, default="published")


class RiskTheme(Base):
    __tablename__ = "risk_theme"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("risk_theme.id"))
    impact_dimensions_json: Mapped[str] = mapped_column(Text, default="[]")


class ControlCatalog(Base):
    __tablename__ = "control_catalog"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    version: Mapped[str | None] = mapped_column(Text)
    publisher: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    license_name: Mapped[str | None] = mapped_column(Text)


class Control(Base, TimestampMixin):
    __tablename__ = "control"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    catalog_id: Mapped[str | None] = mapped_column(ForeignKey("control_catalog.id"))
    external_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    control_type: Mapped[str] = mapped_column(Text, default="technical")
    csf_function: Mapped[str] = mapped_column(Text, nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(Text, default="published")
    catalog: Mapped[ControlCatalog | None] = relationship()


class EntityRelation(Base, TimestampMixin):
    __tablename__ = "entity_relation"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    subject_type: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False)
    predicate: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    object_id: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("source.id"))
    confidence: Mapped[str] = mapped_column(Text, default="medium")
    created_by: Mapped[str] = mapped_column(Text, default="human")
    review_status: Mapped[str] = mapped_column(Text, default="pending_review")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[Source | None] = relationship()

    __table_args__ = (
        UniqueConstraint("subject_type", "subject_id", "predicate", "object_type", "object_id"),
        Index("ix_relation_subject", "subject_type", "subject_id"),
        Index("ix_relation_object", "object_type", "object_id"),
    )


class SearchChunk(Base, TimestampMixin):
    __tablename__ = "search_chunk"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("source.id"))
    published_at: Mapped[date | None] = mapped_column(Date)
    language: Mapped[str] = mapped_column(Text, default="zh")
    topics_json: Mapped[str] = mapped_column(Text, default="[]")
    review_status: Mapped[str] = mapped_column(Text, default="published")
    chunk_path: Mapped[str] = mapped_column(Text, default="root")
    embedding_json: Mapped[str | None] = mapped_column(Text)
    embedding_model: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_search_entity", "entity_type", "entity_id"),)


class DemoScenario(Base, TimestampMixin):
    __tablename__ = "demo_scenario"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    data_flow: Mapped[str] = mapped_column(Text, nullable=False)
    review_status: Mapped[str] = mapped_column(Text, default="published")


class ScenarioAsset(Base):
    __tablename__ = "scenario_asset"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    scenario_id: Mapped[str] = mapped_column(ForeignKey("demo_scenario.id"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    asset_type: Mapped[str] = mapped_column(Text, nullable=False)
    sensitivity: Mapped[str] = mapped_column(Text, default="medium")


class ScenarioRisk(Base):
    __tablename__ = "scenario_risk"

    id: Mapped[str] = mapped_column(Text, primary_key=True, default=new_uuid)
    scenario_id: Mapped[str] = mapped_column(ForeignKey("demo_scenario.id"), nullable=False)
    risk_theme_id: Mapped[str] = mapped_column(ForeignKey("risk_theme.id"), nullable=False)
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False)
    impact: Mapped[int] = mapped_column(Integer, nullable=False)
    current_level: Mapped[str] = mapped_column(Text, nullable=False)
    residual_likelihood: Mapped[int | None] = mapped_column(Integer)
    residual_impact: Mapped[int | None] = mapped_column(Integer)
    residual_level: Mapped[str | None] = mapped_column(Text)
    evidence_strength: Mapped[str] = mapped_column(Text, default="medium")
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
