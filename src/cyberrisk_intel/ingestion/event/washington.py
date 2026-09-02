from __future__ import annotations

import csv
import io
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
    ThreatPattern,
)
from cyberrisk_intel.db.repository import json_dump
from cyberrisk_intel.ingestion.base import IngestionStats
from cyberrisk_intel.ingestion.http import download
from cyberrisk_intel.ingestion.provenance import record_download

WASHINGTON_BREACH_URL = (
    "https://data.wa.gov/api/v3/views/sb4j-ca4h/export.csv?accessType=DOWNLOAD"
)
WASHINGTON_PERSONAL_INFO_URL = (
    "https://data.wa.gov/api/v3/views/padd-mby7/export.csv?accessType=DOWNLOAD"
)


@dataclass(frozen=True)
class WashingtonBreach:
    external_id: str
    organization: str
    date_aware: date | None
    date_submitted: date
    incident_start: date | None
    incident_end: date | None
    breach_cause: str
    cyberattack_type: str | None
    residents_affected: int | None
    industry_type: str | None
    business_type: str | None
    affected_data: tuple[str, ...]


def _clean_id(value: str) -> str:
    return value.replace(",", "").strip()


def _parse_date(value: str) -> date | None:
    text = value.strip()
    if not text:
        return None
    for pattern in ("%Y %b %d %I:%M:%S %p", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, pattern).date()
        except ValueError:
            continue
    raise ValueError(f"Unsupported Washington date: {value}")


def _parse_count(value: str) -> int | None:
    text = value.replace(",", "").strip()
    return int(text) if text.isdigit() else None


def parse_washington_breaches(
    main_payload: bytes, personal_info_payload: bytes
) -> list[WashingtonBreach]:
    personal_info: dict[str, set[str]] = {}
    detail_reader = csv.DictReader(
        io.StringIO(personal_info_payload.decode("utf-8-sig", errors="replace"))
    )
    for row in detail_reader:
        record_id = _clean_id(row.get("Id", ""))
        information_type = row.get("InformationType", "").strip()
        if record_id and information_type:
            personal_info.setdefault(record_id, set()).add(information_type)

    reader = csv.DictReader(io.StringIO(main_payload.decode("utf-8-sig", errors="replace")))
    records: list[WashingtonBreach] = []
    seen: set[str] = set()
    for row in reader:
        record_id = _clean_id(row.get("Id", ""))
        organization = row.get("Name", "").strip()
        submitted = _parse_date(row.get("DateSubmitted", ""))
        if not record_id or not organization or submitted is None or record_id in seen:
            continue
        seen.add(record_id)
        records.append(
            WashingtonBreach(
                external_id=f"WA-AGO-{record_id}",
                organization=organization,
                date_aware=_parse_date(row.get("DateAware", "")),
                date_submitted=submitted,
                incident_start=_parse_date(row.get("DateStart", "")),
                incident_end=_parse_date(row.get("DateEnd", "")),
                breach_cause=row.get("DataBreachCause", "").strip() or "Unknown",
                cyberattack_type=row.get("CyberattackType", "").strip() or None,
                residents_affected=_parse_count(row.get("WashingtoniansAffected", "")),
                industry_type=row.get("IndustryType", "").strip() or None,
                business_type=row.get("BusinessType", "").strip() or None,
                affected_data=tuple(sorted(personal_info.get(record_id, set()))),
            )
        )
    if not records:
        raise ValueError("Washington breach datasets contained no matching records")
    return sorted(records, key=lambda item: (item.date_submitted, item.external_id), reverse=True)


def _industry_name(record: WashingtonBreach) -> str:
    industry_map = {
        "Health": "医疗健康",
        "Finance": "金融",
        "Government": "政府与公共部门",
        "Education": "教育科研",
    }
    if record.industry_type in industry_map:
        return industry_map[record.industry_type]
    business_map = {
        "Software": "信息技术与互联网",
        "Technology": "信息技术与互联网",
        "Retail": "零售与电子商务",
        "Clothing": "零售与电子商务",
        "Manufacturing": "制造业",
        "Transportation": "交通运输",
    }
    return business_map.get(record.business_type or "", "跨行业")


def _threat_name(record: WashingtonBreach) -> str | None:
    mapping = {
        "Ransomware": "勒索软件",
        "Malware": "恶意软件",
        "Phishing": "钓鱼与社会工程",
    }
    return mapping.get(record.cyberattack_type or "")


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


def sync_washington_breaches(
    session: Session,
    main_payload: bytes | None = None,
    personal_info_payload: bytes | None = None,
    *,
    limit: int = 25,
) -> IngestionStats:
    if not 1 <= limit <= 100:
        raise ValueError("Washington import limit must be between 1 and 100")
    if (main_payload is None) != (personal_info_payload is None):
        raise ValueError("Washington main and personal-information payloads are both required")

    run = IngestionRun(adapter="washington-ago-breach-open-data")
    session.add(run)
    if main_payload is None:
        main_download = download(WASHINGTON_BREACH_URL)
        detail_download = download(WASHINGTON_PERSONAL_INFO_URL)
        main_source, _ = record_download(
            session,
            main_download,
            source_name="Washington AGO Data Breach Notifications",
            publisher="Washington State Office of the Attorney General",
            source_type="washington-ago-breaches",
            region="US-WA",
        )
        detail_source, _ = record_download(
            session,
            detail_download,
            source_name="Washington AGO Breached Personal Information Breakdown",
            publisher="Washington State Office of the Attorney General",
            source_type="washington-ago-personal-info",
            region="US-WA",
        )
        main_payload = main_download.content
        personal_info_payload = detail_download.content
    else:
        from cyberrisk_intel.db.repository import get_or_create_source

        main_source = get_or_create_source(
            session,
            name="Washington AGO Data Breach Notifications",
            url=WASHINGTON_BREACH_URL,
            publisher="Washington State Office of the Attorney General",
            source_type="government_open_data",
            region="US-WA",
            reliability="high",
        )
        detail_source = get_or_create_source(
            session,
            name="Washington AGO Breached Personal Information Breakdown",
            url=WASHINGTON_PERSONAL_INFO_URL,
            publisher="Washington State Office of the Attorney General",
            source_type="government_open_data",
            region="US-WA",
            reliability="high",
        )
    assert main_payload is not None and personal_info_payload is not None
    records = parse_washington_breaches(main_payload, personal_info_payload)[:limit]

    industries = {item.name: item for item in session.scalars(select(Industry))}
    risk_by_name = {item.name: item for item in session.scalars(select(RiskTheme))}
    threat_by_name = {item.name: item for item in session.scalars(select(ThreatPattern))}
    created = updated = 0
    for record in records:
        industry = industries[_industry_name(record)]
        attack_label = record.cyberattack_type or record.breach_cause
        affected_count = (
            f"{record.residents_affected:,}" if record.residents_affected is not None else "unknown"
        )
        data_text = ", ".join(record.affected_data) or "not specified"
        summary = (
            f"Washington AGO record {record.external_id.removeprefix('WA-AGO-')} lists "
            f"{record.organization}, submitted on {record.date_submitted.isoformat()}, with "
            f"{affected_count} Washington residents affected. Cause classification: "
            f"{attack_label}. Information types: {data_text}."
        )
        event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == record.external_id)
        )
        if event is None:
            event = SecurityEvent(
                external_id=record.external_id,
                title=f"{record.organization} — Washington breach report",
                summary=summary,
                incident_date=record.incident_start,
                review_status="pending_review",
            )
            session.add(event)
            created += 1
        else:
            updated += 1
        event.title = f"{record.organization} — Washington breach report"
        event.title_zh = f"华盛顿州数据泄露报告：{record.organization}"
        event.summary = summary
        event.summary_zh = (
            f"华盛顿州 AGO 记录显示，{record.organization}于"
            f"{record.date_submitted.isoformat()}提交数据泄露通知，影响该州居民"
            f"{affected_count}人；官方原因分类为{attack_label}。技术根因、CVE 和"
            "ATT&CK Technique 未由该汇总数据直接确认。"
        )
        event.incident_date = record.incident_start
        event.incident_end_date = record.incident_end
        event.discovered_date = record.date_aware
        event.disclosed_date = record.date_submitted
        event.region = "US-WA"
        event.organization = record.organization
        event.organization_type = " / ".join(
            part for part in (record.industry_type, record.business_type) if part
        ) or None
        event.industry_id = industry.id
        event.root_cause = None
        event.affected_assets_json = json_dump([])
        event.affected_data_json = json_dump(list(record.affected_data))
        event.impact = f"{affected_count} Washington residents reported affected."
        event.source_severity = "unknown"
        event.normalized_severity = "unknown"
        event.confidence = "high"
        session.flush()

        for source, evidence, primary in (
            (main_source, summary, True),
            (
                detail_source,
                f"Information types for {record.external_id}: {data_text}.",
                False,
            ),
        ):
            if session.get(EventSource, {"event_id": event.id, "source_id": source.id}) is None:
                session.add(
                    EventSource(
                        event_id=event.id,
                        source_id=source.id,
                        evidence_excerpt=evidence,
                        is_primary=primary,
                    )
                )
        _ensure_relation(
            session,
            event,
            predicate="candidate_affects",
            object_type="industry",
            object_id=industry.id,
            evidence=(
                f"Washington dataset industry fields: {record.industry_type or 'unknown'} / "
                f"{record.business_type or 'unknown'}."
            ),
            source_id=main_source.id,
        )
        for risk_name in ("数据泄露与暴露", "个人信息与隐私风险"):
            risk = risk_by_name.get(risk_name)
            if risk is not None:
                _ensure_relation(
                    session,
                    event,
                    predicate="candidate_materializes",
                    object_type="risk_theme",
                    object_id=risk.id,
                    evidence="Washington AGO record identifies affected residents and data types.",
                    source_id=main_source.id,
                )
        if record.cyberattack_type == "Ransomware":
            risk = risk_by_name.get("勒索与破坏")
            if risk is not None:
                _ensure_relation(
                    session,
                    event,
                    predicate="candidate_materializes",
                    object_type="risk_theme",
                    object_id=risk.id,
                    evidence="Washington AGO cyberattack type is Ransomware.",
                    source_id=main_source.id,
                )
        threat_name = _threat_name(record)
        threat = threat_by_name.get(threat_name or "")
        if threat is not None:
            _ensure_relation(
                session,
                event,
                predicate="candidate_uses",
                object_type="threat_pattern",
                object_id=threat.id,
                evidence=f"Washington AGO cyberattack type is {record.cyberattack_type}.",
                source_id=main_source.id,
            )

    run.discovered = len(records)
    run.created = created
    run.updated = updated
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(records), created, updated, 0)
