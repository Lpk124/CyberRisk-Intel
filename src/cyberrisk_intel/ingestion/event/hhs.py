from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, date, datetime

from bs4 import BeautifulSoup
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
from cyberrisk_intel.db.repository import json_dump
from cyberrisk_intel.ingestion.base import IngestionStats
from cyberrisk_intel.ingestion.http import download
from cyberrisk_intel.ingestion.provenance import record_download

HHS_BREACH_URL = "https://ocrportal.hhs.gov/ocr/breach/breach_report_hip.jsf"


@dataclass(frozen=True)
class HHSBreach:
    external_id: str
    covered_entity: str
    state: str
    entity_type: str
    individuals_affected: int
    submission_date: date
    breach_type: str
    location: str
    business_associate_present: str
    web_description: str


def _external_id(values: list[str]) -> str:
    digest = hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()[:20].upper()
    return f"HHS-OCR-{digest}"


def parse_hhs_breaches(payload: bytes) -> list[HHSBreach]:
    soup = BeautifulSoup(payload, "html.parser")
    report_table = next(
        (
            table
            for table in soup.select("table")
            if "Name of Covered Entity"
            in {cell.get_text(" ", strip=True) for cell in table.select("th")}
        ),
        None,
    )
    if report_table is None:
        raise ValueError("HHS breach report table was not found")

    records: list[HHSBreach] = []
    for row in report_table.select("tbody tr"):
        cells = [cell.get_text(" ", strip=True) for cell in row.find_all("td", recursive=False)]
        if len(cells) < 10:
            continue
        values = cells[1:10]
        if not values[0] or not values[4]:
            continue
        row_id_value = row.get("data-rk")
        official_row_id = row_id_value.strip() if isinstance(row_id_value, str) else ""
        records.append(
            HHSBreach(
                external_id=(
                    f"HHS-OCR-{official_row_id}"
                    if official_row_id
                    else _external_id(values[:7])
                ),
                covered_entity=values[0],
                state=values[1],
                entity_type=values[2],
                individuals_affected=int(values[3].replace(",", "")),
                submission_date=datetime.strptime(values[4], "%m/%d/%Y").date(),
                breach_type=values[5],
                location=values[6],
                business_associate_present=values[7],
                web_description=values[8],
            )
        )
    if not records:
        raise ValueError("HHS breach report contained no parseable records")
    return records


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


def sync_hhs_breaches(
    session: Session, payload: bytes | None = None, *, limit: int = 25
) -> IngestionStats:
    if not 1 <= limit <= 100:
        raise ValueError("HHS import limit must be between 1 and 100")
    run = IngestionRun(adapter="hhs-ocr-breach-portal")
    session.add(run)

    payload_data = payload
    if payload_data is None:
        downloaded = download(HHS_BREACH_URL)
        source, _ = record_download(
            session,
            downloaded,
            source_name="HHS OCR Breach Portal",
            publisher="U.S. Department of Health and Human Services",
            source_type="hhs-ocr-breaches",
            region="US",
        )
        payload_data = downloaded.content
    else:
        from cyberrisk_intel.db.repository import get_or_create_source

        source = get_or_create_source(
            session,
            name="HHS OCR Breach Portal",
            url=HHS_BREACH_URL,
            publisher="U.S. Department of Health and Human Services",
            source_type="government_breach_portal",
            region="US",
            reliability="high",
        )

    all_records = parse_hhs_breaches(payload_data)
    # Older builds derived HHS IDs from mutable display fields. Migrate every row visible in
    # the downloaded page before applying the import limit, so records shifted below the first
    # batch by new disclosures still acquire the portal's stable data-rk identifier.
    for record in all_records:
        official_event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == record.external_id)
        )
        if official_event is not None:
            continue
        legacy_event = session.scalar(
            select(SecurityEvent)
            .join(EventSource, EventSource.event_id == SecurityEvent.id)
            .where(
                EventSource.source_id == source.id,
                SecurityEvent.organization == record.covered_entity,
                SecurityEvent.disclosed_date == record.submission_date,
            )
        )
        if legacy_event is not None:
            legacy_event.external_id = record.external_id
    session.flush()
    records = all_records[:limit]
    industry = session.scalar(select(Industry).where(Industry.name == "医疗健康"))
    if industry is None:
        industry = Industry(code="HEALTH", name="医疗健康", description="Healthcare sector")
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
    for record in records:
        summary = (
            f"HHS OCR lists {record.covered_entity} ({record.state}) with a "
            f"{record.breach_type} report submitted on {record.submission_date.isoformat()}, "
            f"affecting {record.individuals_affected:,} individuals; the listed information "
            f"location is {record.location or 'not specified'}."
        )
        event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == record.external_id)
        )
        if event is None:
            event = SecurityEvent(
                external_id=record.external_id,
                title=f"{record.covered_entity} — HHS breach report",
                incident_date=None,
                summary=summary,
                review_status="pending_review",
            )
            session.add(event)
            created += 1
        else:
            updated += 1
        event.title = f"{record.covered_entity} — HHS breach report"
        event.title_zh = f"HHS OCR 收录：{record.covered_entity} 医疗信息泄露报告"
        event.summary = summary
        event.summary_zh = (
            f"HHS OCR 记录显示，{record.covered_entity} 于"
            f"{record.submission_date.isoformat()}提交{record.breach_type}报告，"
            f"涉及{record.individuals_affected:,}人；所列信息位置为"
            f"{record.location or '未说明'}。事件发生日期和技术根因尚待补充核验。"
        )
        event.disclosed_date = record.submission_date
        event.region = "US"
        event.organization = record.covered_entity
        event.organization_type = record.entity_type
        event.industry_id = industry.id
        event.root_cause = None
        event.affected_assets_json = json_dump([record.location] if record.location else [])
        event.affected_data_json = json_dump(["protected health information"])
        event.impact = f"{record.individuals_affected:,} individuals reported affected to HHS OCR."
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
            predicate="affects",
            object_type="industry",
            object_id=industry.id,
            evidence=f"HHS covered entity type: {record.entity_type}.",
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
                    "HHS breach portal record concerns unsecured protected health information; "
                    "relationship requires human review."
                ),
                source_id=source.id,
            )

    run.discovered = len(records)
    run.created = created
    run.updated = updated
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    session.flush()
    return IngestionStats(len(records), created, updated, 0)
