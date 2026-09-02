from __future__ import annotations

import csv
import hashlib
import io
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import (
    EntityRelation,
    EventSource,
    Industry,
    IngestionRun,
    RiskTheme,
    SecurityEvent,
)
from cyberrisk_intel.db.repository import get_or_create_source, json_dump
from cyberrisk_intel.ingestion.base import IngestionStats
from cyberrisk_intel.ingestion.http import download
from cyberrisk_intel.ingestion.provenance import record_download

CALIFORNIA_BREACH_CSV_URL = "https://www.oag.ca.gov/privacy/databreach/list-export"
DATE_PATTERN = re.compile(r"\d{2}/\d{2}/\d{4}")


@dataclass(frozen=True)
class CaliforniaBreachNotice:
    external_id: str
    organization: str
    incident_start: date | None
    incident_end: date | None
    reported_date: date


def _clean_text(value: str) -> str:
    return re.sub(r"\ufffd+", "'", value).strip()


def _parse_date(value: str) -> date:
    return datetime.strptime(value, "%m/%d/%Y").date()


def _external_id(organization: str, dates: list[date], reported_date: date) -> str:
    material = "|".join(
        [organization.casefold(), *(item.isoformat() for item in dates), reported_date.isoformat()]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20].upper()
    return f"CA-OAG-{digest}"


def parse_california_breaches(payload: bytes) -> list[CaliforniaBreachNotice]:
    text = payload.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    next(reader, None)
    output: list[CaliforniaBreachNotice] = []
    seen: set[str] = set()
    for row in reader:
        if len(row) < 3:
            continue
        organization = _clean_text(row[0])
        reported_text = row[2].strip()
        if not organization or not reported_text:
            continue
        incident_dates = [_parse_date(value) for value in DATE_PATTERN.findall(row[1])]
        reported_date = _parse_date(reported_text)
        external_id = _external_id(organization, incident_dates, reported_date)
        if external_id in seen:
            continue
        seen.add(external_id)
        output.append(
            CaliforniaBreachNotice(
                external_id=external_id,
                organization=organization,
                incident_start=min(incident_dates) if incident_dates else None,
                incident_end=max(incident_dates) if incident_dates else None,
                reported_date=reported_date,
            )
        )
    if not output:
        raise ValueError("California breach CSV contained no parseable records")
    return output


def _normalized_organization(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").casefold())


def _probable_existing_duplicate(
    record: CaliforniaBreachNotice, existing_events: list[SecurityEvent]
) -> bool:
    normalized = _normalized_organization(record.organization)
    for event in existing_events:
        if event.external_id == record.external_id:
            continue
        if _normalized_organization(event.organization) != normalized:
            continue
        if event.disclosed_date and abs((event.disclosed_date - record.reported_date).days) <= 45:
            return True
    return False


def _ensure_relation(
    session: Session,
    event: SecurityEvent,
    *,
    predicate: str,
    object_type: str,
    object_id: str,
    evidence: str,
    source_id: str,
) -> None:
    relation = session.scalar(
        select(EntityRelation).where(
            EntityRelation.subject_type == "security_event",
            EntityRelation.subject_id == event.id,
            EntityRelation.predicate == predicate,
            EntityRelation.object_type == object_type,
            EntityRelation.object_id == object_id,
        )
    )
    if relation is None:
        session.add(
            EntityRelation(
                subject_type="security_event",
                subject_id=event.id,
                predicate=predicate,
                object_type=object_type,
                object_id=object_id,
                evidence_excerpt=evidence,
                source_id=source_id,
                confidence="high",
                created_by="import",
                review_status="pending_review",
            )
        )


def sync_california_breaches(
    session: Session, payload: bytes | None = None, *, limit: int = 25
) -> IngestionStats:
    if not 1 <= limit <= 100:
        raise ValueError("California import limit must be between 1 and 100")
    run = IngestionRun(adapter="california-oag-breach-notices")
    session.add(run)

    payload_data = payload
    if payload_data is None:
        downloaded = download(CALIFORNIA_BREACH_CSV_URL)
        source, _ = record_download(
            session,
            downloaded,
            source_name="California Attorney General Data Breach List",
            publisher="California Department of Justice",
            source_type="california-oag-breaches",
            region="US-CA",
        )
        payload_data = downloaded.content
    else:
        source = get_or_create_source(
            session,
            name="California Attorney General Data Breach List",
            url=CALIFORNIA_BREACH_CSV_URL,
            publisher="California Department of Justice",
            source_type="government_breach_portal",
            region="US-CA",
            reliability="high",
        )

    existing_events = list(session.scalars(select(SecurityEvent)))
    selected: list[CaliforniaBreachNotice] = []
    for record in parse_california_breaches(payload_data):
        if _probable_existing_duplicate(record, existing_events):
            continue
        selected.append(record)
        if len(selected) == limit:
            break

    industry = session.scalar(select(Industry).where(Industry.name == "跨行业"))
    if industry is None:
        industry = Industry(code="CROSS", name="跨行业", description="Cross-sector")
        session.add(industry)
        session.flush()
    risks = list(
        session.scalars(
            select(RiskTheme).where(
                RiskTheme.name.in_(["数据泄露与暴露", "个人信息与隐私风险"])
            )
        )
    )

    created = updated = 0
    for record in selected:
        date_text = (
            record.incident_start.isoformat() if record.incident_start else "not stated"
        )
        if record.incident_end and record.incident_end != record.incident_start:
            date_text += f" through {record.incident_end.isoformat()}"
        summary = (
            f"The California Attorney General breach list records a notice from "
            f"{record.organization}, reported on {record.reported_date.isoformat()}, with "
            f"breach date(s) {date_text}. The notifying organization is not necessarily the "
            "organization where the breach occurred."
        )
        event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == record.external_id)
        )
        if event is None:
            event = SecurityEvent(
                external_id=record.external_id,
                title=f"Data breach notice from {record.organization}",
                incident_date=record.incident_start,
                summary=summary,
                review_status="pending_review",
            )
            session.add(event)
            created += 1
        else:
            updated += 1
        event.title = f"Data breach notice from {record.organization}"
        event.title_zh = f"加州司法部长数据泄露通知：{record.organization}"
        event.summary = summary
        event.summary_zh = (
            f"加州司法部长公开列表收录了{record.organization}提交的数据泄露通知，"
            f"报告日期为{record.reported_date.isoformat()}。通知机构不一定是实际发生"
            "泄露的机构，行业、影响人数、技术根因和攻击方式仍需结合通知正文人工复核。"
        )
        event.incident_date = record.incident_start
        event.incident_end_date = record.incident_end
        event.disclosed_date = record.reported_date
        event.region = "US-CA"
        event.organization = record.organization
        event.organization_type = "notifying_organization"
        event.industry_id = industry.id
        event.root_cause = None
        event.affected_assets_json = json_dump([])
        event.affected_data_json = json_dump(["personal information"])
        event.impact = None
        event.source_severity = "unknown"
        event.normalized_severity = "unknown"
        event.confidence = "high"
        session.flush()

        if session.get(EventSource, {"event_id": event.id, "source_id": source.id}) is None:
            session.add(
                EventSource(
                    event_id=event.id,
                    source_id=source.id,
                    evidence_excerpt=summary,
                    is_primary=True,
                )
            )
        _ensure_relation(
            session,
            event,
            predicate="candidate_affects",
            object_type="industry",
            object_id=industry.id,
            evidence="Industry is unknown at ingestion; cross-sector is a review placeholder.",
            source_id=source.id,
        )
        for risk in risks:
            _ensure_relation(
                session,
                event,
                predicate="candidate_materializes",
                object_type="risk_theme",
                object_id=risk.id,
                evidence=(
                    "California breach notification list concerns acquisition or suspected "
                    "acquisition of unencrypted personal information; relationship needs review."
                ),
                source_id=source.id,
            )

    run.discovered = len(selected)
    run.created = created
    run.updated = updated
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(selected), created, updated, 0)
