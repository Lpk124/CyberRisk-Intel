from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import (
    AttackTechnique,
    Control,
    EntityRelation,
    EventSource,
    Industry,
    IngestionRun,
    Policy,
    PolicyClause,
    PolicyVersion,
    RiskTheme,
    SecurityEvent,
    ThreatPattern,
    Vulnerability,
)
from cyberrisk_intel.db.repository import get_or_create_source, json_dump
from cyberrisk_intel.domain.schemas import EventInput, PolicyInput
from cyberrisk_intel.ingestion.base import IngestionStats


def _load(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        raise ValueError("Import file must contain a JSON array")
    return data


def _code(value: str) -> str:
    latin = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return latin or "industry-" + hashlib.sha256(value.encode()).hexdigest()[:10]


def _run(session: Session, adapter: str, discovered: int) -> IngestionRun:
    run = IngestionRun(adapter=adapter, discovered=discovered)
    session.add(run)
    session.flush()
    return run


def _ensure_relation(
    session: Session,
    *,
    subject_type: str,
    subject_id: str,
    predicate: str,
    object_type: str,
    object_id: str,
    evidence: str,
    source_id: str | None,
    confidence: str,
    review_status: str,
) -> None:
    duplicate = (
        any(
            isinstance(row, EntityRelation)
            and row.subject_type == subject_type
            and row.subject_id == subject_id
            and row.predicate == predicate
            and row.object_type == object_type
            and row.object_id == object_id
            for row in session.new
        )
        or session.scalar(
            select(EntityRelation.id).where(
                EntityRelation.subject_type == subject_type,
                EntityRelation.subject_id == subject_id,
                EntityRelation.predicate == predicate,
                EntityRelation.object_type == object_type,
                EntityRelation.object_id == object_id,
            )
        )
        is not None
    )
    if not duplicate:
        session.add(
            EntityRelation(
                subject_type=subject_type,
                subject_id=subject_id,
                predicate=predicate,
                object_type=object_type,
                object_id=object_id,
                evidence_excerpt=evidence,
                source_id=source_id,
                confidence=confidence,
                created_by="import",
                review_status=review_status,
            )
        )


def import_policies(session: Session, path: Path) -> IngestionStats:
    raw_records = _load(path)
    run = _run(session, "policy-json", len(raw_records))
    created = updated = failed = 0
    for raw in raw_records:
        try:
            item = PolicyInput.model_validate(raw)
            source = get_or_create_source(
                session,
                name=item.source.name,
                url=str(item.source.url),
                publisher=item.source.publisher,
                source_type=item.source.source_type,
                region=item.source.region,
                reliability=item.source.reliability.value,
                license_name=item.source.license_name,
            )
            policy = session.scalar(select(Policy).where(Policy.external_id == item.external_id))
            if policy is None:
                policy = Policy(
                    external_id=item.external_id,
                    title=item.title,
                    issuer=item.issuer,
                    source_id=source.id,
                    summary=item.summary,
                )
                session.add(policy)
                created += 1
            else:
                updated += 1
            policy.title = item.title
            policy.issuer = item.issuer
            policy.jurisdiction = item.jurisdiction
            policy.published_date = item.published_date
            policy.effective_date = item.effective_date
            policy.summary = item.summary
            policy.topics_json = json_dump(item.topics)
            policy.review_status = item.status.value
            policy.source_id = source.id
            session.flush()
            full_text = "\n".join(str(clause.get("body", "")) for clause in item.clauses)
            content = full_text or item.summary
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            version = session.scalar(
                select(PolicyVersion).where(
                    PolicyVersion.policy_id == policy.id,
                    PolicyVersion.content_hash == content_hash,
                )
            )
            if version is None:
                version = PolicyVersion(
                    policy_id=policy.id,
                    version_label="import-v1",
                    content_hash=content_hash,
                    full_text=content,
                    valid_from=item.effective_date,
                )
                session.add(version)
                session.flush()
            for position, clause in enumerate(item.clauses, start=1):
                clause_ref = str(clause.get("clause_ref") or clause.get("ref") or position)
                exists = session.scalar(
                    select(PolicyClause).where(
                        PolicyClause.version_id == version.id,
                        PolicyClause.clause_ref == clause_ref,
                    )
                )
                if exists is None and clause.get("body"):
                    session.add(
                        PolicyClause(
                            version_id=version.id,
                            clause_ref=clause_ref,
                            hierarchy_path=str(clause.get("hierarchy_path", clause_ref)),
                            title=clause.get("title"),
                            body=str(clause["body"]),
                            review_status=item.status.value,
                        )
                    )
        except Exception:
            failed += 1
    run.created = created
    run.updated = updated
    run.failed = failed
    run.status = "completed" if failed == 0 else "completed_with_errors"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(raw_records), created, updated, failed)


def import_events(session: Session, path: Path) -> IngestionStats:
    raw_records = _load(path)
    run = _run(session, "event-json", len(raw_records))
    created = updated = failed = 0
    for raw in raw_records:
        try:
            item = EventInput.model_validate(raw)
            industry = session.scalar(select(Industry).where(Industry.name == item.industry))
            if industry is None:
                industry = Industry(
                    code=_code(item.industry),
                    name=item.industry,
                    description="Created from reviewed event import.",
                )
                session.add(industry)
                session.flush()
            event = session.scalar(
                select(SecurityEvent).where(SecurityEvent.external_id == item.external_id)
            )
            if event is None:
                event = SecurityEvent(
                    external_id=item.external_id,
                    title=item.title,
                    summary=item.summary,
                    incident_date=item.incident_date,
                )
                session.add(event)
                created += 1
            else:
                updated += 1
            event.title = item.title
            event.title_zh = item.title_zh
            event.summary = item.summary
            event.summary_zh = item.summary_zh
            event.incident_date = item.incident_date
            event.disclosed_date = item.disclosed_date
            event.region = item.region
            event.organization = item.organization
            event.organization_type = item.organization_type
            event.industry_id = industry.id
            event.root_cause = item.root_cause
            event.affected_assets_json = json_dump(item.affected_assets)
            event.affected_data_json = json_dump(item.affected_data)
            event.impact = item.impact
            event.source_severity = item.severity.value
            event.normalized_severity = item.severity.value
            event.confidence = item.confidence.value
            event.review_status = item.status.value
            session.flush()
            primary_source_id: str | None = None
            for index, source_input in enumerate(item.sources):
                source = get_or_create_source(
                    session,
                    name=source_input.name,
                    url=str(source_input.url),
                    publisher=source_input.publisher,
                    source_type=source_input.source_type,
                    region=source_input.region,
                    reliability=source_input.reliability.value,
                    license_name=source_input.license_name,
                )
                primary_source_id = primary_source_id or source.id
                if session.get(EventSource, {"event_id": event.id, "source_id": source.id}) is None:
                    session.add(
                        EventSource(
                            event_id=event.id,
                            source_id=source.id,
                            evidence_excerpt=item.summary,
                            is_primary=index == 0,
                        )
                    )
                    session.flush()

            _ensure_relation(
                session=session,
                subject_type="security_event",
                subject_id=event.id,
                predicate="affects",
                object_type="industry",
                object_id=industry.id,
                evidence=f"Reviewed industry classification: {industry.name}.",
                source_id=primary_source_id,
                confidence=item.confidence.value,
                review_status=item.status.value,
            )
            relation_sets = [
                (
                    item.threat_patterns,
                    ThreatPattern,
                    ThreatPattern.name,
                    "uses_or_represents",
                    "threat_pattern",
                    item.summary,
                ),
                (
                    item.risk_themes,
                    RiskTheme,
                    RiskTheme.name,
                    "materializes",
                    "risk_theme",
                    item.impact or item.summary,
                ),
                (
                    item.cve_ids,
                    Vulnerability,
                    Vulnerability.cve_id,
                    "exploits_or_involves",
                    "vulnerability",
                    item.root_cause or item.summary,
                ),
                (
                    item.attack_ids,
                    AttackTechnique,
                    AttackTechnique.attack_id,
                    "observed_technique",
                    "attack_technique",
                    item.root_cause or item.summary,
                ),
                (
                    item.controls,
                    Control,
                    Control.external_id,
                    "mitigated_by",
                    "control",
                    "Reviewed imported control recommendation.",
                ),
            ]
            for identifiers, model, column, predicate, object_type, evidence in relation_sets:
                for identifier in identifiers:
                    target: Any = session.scalar(select(model).where(column == identifier))
                    if target is not None:
                        _ensure_relation(
                            session=session,
                            subject_type="security_event",
                            subject_id=event.id,
                            predicate=predicate,
                            object_type=object_type,
                            object_id=target.id,
                            evidence=evidence,
                            source_id=primary_source_id,
                            confidence=item.confidence.value,
                            review_status=item.status.value,
                        )
        except Exception:
            failed += 1
    run.created = created
    run.updated = updated
    run.failed = failed
    run.status = "completed" if failed == 0 else "completed_with_errors"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(raw_records), created, updated, failed)
