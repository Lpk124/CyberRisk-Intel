from __future__ import annotations

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
        select(SecurityEvent.incident_date, SecurityEvent.normalized_severity)
    ).all()
    if not rows:
        return pd.DataFrame(columns=["month", "severity", "count"])
    frame = pd.DataFrame(rows, columns=["incident_date", "severity"])
    frame["month"] = pd.to_datetime(frame["incident_date"]).dt.to_period("M").astype(str)
    return frame.groupby(["month", "severity"], dropna=False).size().reset_index(name="count")


def event_industry_matrix(session: Session) -> pd.DataFrame:
    rows = session.execute(
        select(
            SecurityEvent.incident_date,
            SecurityEvent.normalized_severity,
            SecurityEvent.industry_id,
        )
    ).all()
    if not rows:
        return pd.DataFrame(columns=["industry_id", "severity", "count"])
    frame = pd.DataFrame(rows, columns=["incident_date", "severity", "industry_id"])
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
