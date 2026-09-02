from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime

from pypdf import PdfReader
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
from cyberrisk_intel.ingestion.http import Download, download
from cyberrisk_intel.ingestion.provenance import record_download

MASSACHUSETTS_BREACH_REPORT_URL_TEMPLATE = (
    "https://www.mass.gov/doc/data-breach-report-{year}/download"
)

ROW_PATTERN = re.compile(
    r"^\s*(?P<breach_id>\d{4}-\d+)\s+"
    r"(?P<reported>\d{2}-[A-Za-z]{3}-\d{2})\s+"
    r"(?P<body>.*?)\s+"
    r"(?P<residents>[\d,]+)\s+"
    r"(?P<ssn>Yes|No)\s+"
    r"(?P<medical>Yes|No)\s+"
    r"(?P<financial>Yes|No)\s+"
    r"(?P<drivers>Yes|No)\s+"
    r"(?P<cards>Yes|No)\s*$"
)

REPORTING_TYPES = (
    "Financial Services Company",
    "Banks & Credit Unions",
    "Insurance Company",
    "Federal Government",
    "State Government",
    "Local Government",
    "Not-for-profit",
    "Manufacturing",
    "Health Care",
    "Technology",
    "Commercial",
    "Educational",
    "Retail",
    "Other",
)

TYPE_TO_INDUSTRY = {
    "Financial Services Company": "金融",
    "Banks & Credit Unions": "金融",
    "Insurance Company": "金融",
    "Federal Government": "政府与公共部门",
    "State Government": "政府与公共部门",
    "Local Government": "政府与公共部门",
    "Manufacturing": "制造业",
    "Health Care": "医疗健康",
    "Technology": "信息技术与互联网",
    "Educational": "教育科研",
    "Retail": "零售与电子商务",
}

DATA_COLUMNS = {
    "ssn": "Social Security number",
    "medical": "medical records",
    "financial": "financial account information",
    "drivers": "driver's license information",
    "cards": "credit or debit card number",
}


@dataclass(frozen=True)
class MassachusettsBreachReport:
    external_id: str
    organization: str
    reporting_type: str
    reported_date: date
    residents_affected: int
    affected_data: tuple[str, ...]


def _is_continuation(line: str) -> bool:
    text = line.strip()
    if not text or ROW_PATTERN.match(line) or re.match(r"^\s*\d{4}-\d+\b", line):
        return False
    header_markers = (
        "Data Breach Notification Report",
        "total number of breaches",
        "Reporting Organization Name",
        "Breach",
        "Number",
        "To OCA",
    )
    return not any(marker in text for marker in header_markers)


def _split_organization_and_type(body: str) -> tuple[str, str] | None:
    normalized = " ".join(body.split())
    for reporting_type in REPORTING_TYPES:
        if normalized.endswith(reporting_type):
            organization = normalized[: -len(reporting_type)].strip()
            if organization:
                return organization, reporting_type
    return None


def parse_massachusetts_report_text(text: str) -> list[MassachusettsBreachReport]:
    """Parse only complete, single-line rows from the official fixed-layout report.

    Rows adjacent to wrapped text are deliberately skipped. This avoids turning partial
    organization names or organization-type fragments into asserted facts.
    """
    records: list[MassachusettsBreachReport] = []
    seen: set[str] = set()
    for page in text.split("\f"):
        lines = page.splitlines()
        for index, line in enumerate(lines):
            match = ROW_PATTERN.match(line)
            if match is None:
                continue
            previous_is_continuation = index > 0 and _is_continuation(lines[index - 1])
            next_is_continuation = index + 1 < len(lines) and _is_continuation(lines[index + 1])
            if previous_is_continuation or next_is_continuation:
                continue
            split = _split_organization_and_type(match.group("body"))
            if split is None:
                continue
            organization, reporting_type = split
            external_id = f"MA-OCABR-{match.group('breach_id')}"
            if external_id in seen:
                continue
            seen.add(external_id)
            affected_data = tuple(
                label
                for key, label in DATA_COLUMNS.items()
                if match.group(key) == "Yes"
            )
            records.append(
                MassachusettsBreachReport(
                    external_id=external_id,
                    organization=organization,
                    reporting_type=reporting_type,
                    reported_date=datetime.strptime(
                        match.group("reported"), "%d-%b-%y"
                    ).date(),
                    residents_affected=int(match.group("residents").replace(",", "")),
                    affected_data=affected_data,
                )
            )
    if not records:
        raise ValueError("Massachusetts breach report contained no complete rows")
    return records


def parse_massachusetts_breach_pdf(payload: bytes) -> list[MassachusettsBreachReport]:
    pages = [
        page.extract_text(extraction_mode="layout")
        for page in PdfReader(io.BytesIO(payload)).pages
    ]
    return parse_massachusetts_report_text("\f".join(pages))


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


def sync_massachusetts_breaches(
    session: Session,
    payload: bytes | None = None,
    *,
    limit: int = 25,
    year: int = date.today().year,
    extracted_text: str | None = None,
) -> IngestionStats:
    if not 1 <= limit <= 100:
        raise ValueError("Massachusetts import limit must be between 1 and 100")
    if payload is not None and extracted_text is not None:
        raise ValueError("Provide either PDF payload or extracted text, not both")
    if not 2007 <= year <= date.today().year:
        raise ValueError("Massachusetts report year is outside the supported range")

    run = IngestionRun(adapter="massachusetts-ocabr-breach-report")
    session.add(run)
    report_url = MASSACHUSETTS_BREACH_REPORT_URL_TEMPLATE.format(year=year)
    payload_data = payload
    if extracted_text is None:
        if payload_data is None:
            downloaded = download(report_url)
            source, _ = record_download(
                session,
                downloaded,
                source_name=f"Massachusetts OCABR Data Breach Notification Report {year}",
                publisher="Massachusetts Office of Consumer Affairs and Business Regulation",
                source_type="massachusetts-ocabr-breaches",
                region="US-MA",
            )
            payload_data = downloaded.content
        else:
            source, _ = record_download(
                session,
                Download(
                    url=report_url,
                    content=payload_data,
                    content_type="application/pdf",
                    sha256=hashlib.sha256(payload_data).hexdigest(),
                ),
                source_name=f"Massachusetts OCABR Data Breach Notification Report {year}",
                publisher=(
                    "Massachusetts Office of Consumer Affairs and Business Regulation"
                ),
                source_type="massachusetts-ocabr-breaches",
                region="US-MA",
            )
        assert payload_data is not None
        records = parse_massachusetts_breach_pdf(payload_data)
    else:
        from cyberrisk_intel.db.repository import get_or_create_source

        source = get_or_create_source(
            session,
            name=f"Massachusetts OCABR Data Breach Notification Report {year}",
            url=report_url,
            publisher="Massachusetts Office of Consumer Affairs and Business Regulation",
            source_type="government_breach_report",
            region="US-MA",
            reliability="high",
        )
        records = parse_massachusetts_report_text(extracted_text)

    selected = records[:limit]
    risks = list(
        session.scalars(
            select(RiskTheme).where(
                RiskTheme.name.in_(["数据泄露与暴露", "个人信息与隐私风险"])
            )
        )
    )
    industries = {item.name: item for item in session.scalars(select(Industry))}
    fallback = industries.get("跨行业")
    if fallback is None:
        fallback = Industry(code="CROSS", name="跨行业", description="Cross-sector")
        session.add(fallback)
        session.flush()
        industries[fallback.name] = fallback

    created = updated = 0
    for record in selected:
        industry = industries.get(TYPE_TO_INDUSTRY.get(record.reporting_type, ""), fallback)
        data_text = ", ".join(record.affected_data) or "none of the report's five categories"
        summary = (
            f"Massachusetts OCABR report {record.external_id.removeprefix('MA-OCABR-')} "
            f"lists {record.organization}, reported on {record.reported_date.isoformat()}, "
            f"with {record.residents_affected:,} Massachusetts residents affected. "
            f"Marked data categories: {data_text}."
        )
        event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == record.external_id)
        )
        if event is None:
            event = SecurityEvent(
                external_id=record.external_id,
                title=f"{record.organization} — Massachusetts breach report",
                summary=summary,
                incident_date=None,
                review_status="pending_review",
            )
            session.add(event)
            created += 1
        else:
            updated += 1
        event.title = f"{record.organization} — Massachusetts breach report"
        event.title_zh = f"马萨诸塞州数据泄露报告：{record.organization}"
        event.summary = summary
        event.summary_zh = (
            f"马萨诸塞州 OCABR 报告记录了{record.organization}的数据泄露通知，"
            f"报告日期为{record.reported_date.isoformat()}，涉及该州居民"
            f"{record.residents_affected:,}人。事件发生日期、技术根因及攻击方式"
            "未在年度汇总表中说明，仍需结合通知正文人工复核。"
        )
        event.incident_date = None
        event.incident_end_date = None
        event.disclosed_date = record.reported_date
        event.region = "US-MA"
        event.organization = record.organization
        event.organization_type = record.reporting_type
        event.industry_id = industry.id
        event.root_cause = None
        event.affected_assets_json = json_dump([])
        event.affected_data_json = json_dump(list(record.affected_data))
        event.impact = f"{record.residents_affected:,} Massachusetts residents reported affected."
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
            evidence=f"OCABR reporting organization type: {record.reporting_type}.",
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
                    "OCABR report records affected residents and personal-data categories; "
                    "the relationship remains pending human review."
                ),
                source_id=source.id,
            )

    run.discovered = len(selected)
    run.created = created
    run.updated = updated
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(selected), created, updated, 0)
