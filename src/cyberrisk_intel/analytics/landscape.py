from __future__ import annotations

import json
from datetime import UTC, datetime

import pandas as pd
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import (
    AttackTechnique,
    EntityRelation,
    EventSource,
    Policy,
    SecurityEvent,
    Source,
    Vulnerability,
)


def overview_metrics(session: Session) -> dict[str, int | str]:
    return {
        "policies": session.scalar(select(func.count()).select_from(Policy)) or 0,
        "events": session.scalar(select(func.count()).select_from(SecurityEvent)) or 0,
        "published_events": session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.review_status == "published")
        )
        or 0,
        "pending_events": session.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.review_status == "pending_review")
        )
        or 0,
        "vulnerabilities": session.scalar(select(func.count()).select_from(Vulnerability)) or 0,
        "attack_techniques": session.scalar(select(func.count()).select_from(AttackTechnique)) or 0,
        "kev": session.scalar(
            select(func.count()).select_from(Vulnerability).where(Vulnerability.is_kev)
        )
        or 0,
        "relations": session.scalar(select(func.count()).select_from(EntityRelation)) or 0,
        "sources": session.scalar(select(func.count()).select_from(Source)) or 0,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def monthly_events(session: Session) -> pd.DataFrame:
    rows = session.execute(
        select(
            SecurityEvent.incident_date,
            SecurityEvent.disclosed_date,
            SecurityEvent.normalized_severity,
        )
    ).all()
    if not rows:
        return pd.DataFrame(columns=["month", "severity", "date_basis", "count"])
    frame = pd.DataFrame(rows, columns=["incident_date", "disclosed_date", "severity"])
    frame["analysis_date"] = frame["incident_date"].fillna(frame["disclosed_date"])
    frame["date_basis"] = frame["incident_date"].notna().map(
        {True: "incident_date", False: "disclosed_date"}
    )
    frame = frame.dropna(subset=["analysis_date"])
    frame["month"] = pd.to_datetime(frame["analysis_date"]).dt.to_period("M").astype(str)
    return (
        frame.groupby(["month", "severity", "date_basis"], dropna=False)
        .size()
        .reset_index(name="count")
    )


def policy_document_distribution(session: Session) -> pd.DataFrame:
    rows = session.execute(
        select(Policy.document_type, func.count(Policy.id)).group_by(Policy.document_type)
    ).all()
    return pd.DataFrame(rows, columns=["document_type", "count"])


def policy_topic_timeline(session: Session) -> pd.DataFrame:
    rows = session.execute(select(Policy.published_date, Policy.topics_json)).all()
    records: list[dict[str, int | str]] = []
    for published_date, topics_json in rows:
        if published_date is None:
            continue
        topics = json.loads(topics_json or "[]")
        for topic in topics:
            records.append({"year": published_date.year, "topic": str(topic)})
    if not records:
        return pd.DataFrame(columns=["year", "topic", "count", "share", "sample_size"])
    frame = pd.DataFrame(records)
    grouped = frame.groupby(["year", "topic"], as_index=False).size().rename(
        columns={"size": "count"}
    )
    sample_sizes = frame.groupby("year").size().rename("sample_size")
    grouped = grouped.merge(sample_sizes, on="year")
    grouped["share"] = grouped["count"] / grouped["sample_size"]
    return grouped


def event_industry_matrix(session: Session) -> pd.DataFrame:
    rows = session.execute(
        select(
            SecurityEvent.incident_date,
            SecurityEvent.disclosed_date,
            SecurityEvent.normalized_severity,
            SecurityEvent.industry_id,
        )
    ).all()
    if not rows:
        return pd.DataFrame(columns=["industry_id", "severity", "count"])
    frame = pd.DataFrame(
        rows, columns=["incident_date", "disclosed_date", "severity", "industry_id"]
    )
    return frame.groupby(["industry_id", "severity"], dropna=False).size().reset_index(name="count")


def relation_distribution(session: Session, object_type: str) -> pd.DataFrame:
    rows = session.execute(
        select(EntityRelation.object_id, func.count(EntityRelation.id))
        .where(
            EntityRelation.object_type == object_type, EntityRelation.review_status == "published"
        )
        .group_by(EntityRelation.object_id)
    ).all()
    return pd.DataFrame(rows, columns=["entity_id", "count"])


def event_source_coverage(session: Session) -> pd.DataFrame:
    rows = session.execute(
        select(
            Source.name,
            Source.publisher,
            Source.region,
            Source.source_type,
            func.count(EventSource.event_id.distinct()),
        )
        .join(EventSource, EventSource.source_id == Source.id)
        .group_by(Source.id, Source.name, Source.publisher, Source.region, Source.source_type)
        .order_by(func.count(EventSource.event_id.distinct()).desc())
    ).all()
    frame = pd.DataFrame(
        rows, columns=["source", "publisher", "region", "source_type", "event_count"]
    )
    if frame.empty:
        frame["share"] = pd.Series(dtype=float)
        return frame
    total_events = session.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    frame["share"] = frame["event_count"] / total_events if total_events else 0.0
    return frame


def data_quality(session: Session) -> pd.DataFrame:
    events = list(session.scalars(select(SecurityEvent)))
    total = len(events)
    checks = {
        "事件含来源": sum(
            bool(
                session.scalar(
                    select(func.count())
                    .select_from(EventSource)
                    .where(EventSource.event_id == event.id)
                )
            )
            for event in events
        ),
        "事件已复核": sum(event.review_status == "published" for event in events),
        "事件有已知发生日期": sum(event.incident_date is not None for event in events),
        "事件有披露日期": sum(event.disclosed_date is not None for event in events),
        "事件有根因": sum(bool(event.root_cause) for event in events),
        "事件有行业": sum(bool(event.industry_id) for event in events),
    }
    return pd.DataFrame(
        [
            {
                "metric": name,
                "count": value,
                "sample_size": total,
                "rate": (value / total if total else 0.0),
            }
            for name, value in checks.items()
        ]
    )
