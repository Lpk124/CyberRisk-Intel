from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import (
    AttackTechnique,
    Control,
    EntityRelation,
    Industry,
    Policy,
    RiskTheme,
    SecurityEvent,
    Source,
    ThreatPattern,
    Vulnerability,
)

ENTITY_MODELS: dict[str, type[Any]] = {
    "policy": Policy,
    "security_event": SecurityEvent,
    "vulnerability": Vulnerability,
    "attack_technique": AttackTechnique,
    "risk_theme": RiskTheme,
    "industry": Industry,
    "control": Control,
    "threat_pattern": ThreatPattern,
}


def json_dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def json_load(value: str | None) -> Any:
    if not value:
        return []
    return json.loads(value)


def get_or_create_source(
    session: Session,
    *,
    name: str,
    url: str,
    publisher: str,
    source_type: str,
    region: str = "Global",
    reliability: str = "medium",
    license_name: str | None = None,
) -> Source:
    source = session.scalar(select(Source).where(Source.url == url))
    if source is None:
        source = Source(
            name=name,
            url=url,
            publisher=publisher,
            source_type=source_type,
            region=region,
            reliability=reliability,
            license_name=license_name,
        )
        session.add(source)
        session.flush()
    return source


def get_entity(session: Session, entity_type: str, entity_id: str) -> Any | None:
    model = ENTITY_MODELS.get(entity_type)
    if model is None:
        return None
    return session.get(model, entity_id)


def entity_label(entity_type: str, entity: Any) -> str:
    for key in ("title_zh", "title", "name", "cve_id", "attack_id", "code"):
        value = getattr(entity, key, None)
        if value:
            return str(value)
    return f"{entity_type}:{getattr(entity, 'id', 'unknown')}"


def iter_entities(session: Session, entity_type: str) -> Iterable[Any]:
    model = ENTITY_MODELS[entity_type]
    return session.scalars(select(model)).all()


def relation_exists(
    session: Session,
    subject_type: str,
    subject_id: str,
    predicate: str,
    object_type: str,
    object_id: str,
) -> bool:
    statement = select(EntityRelation.id).where(
        EntityRelation.subject_type == subject_type,
        EntityRelation.subject_id == subject_id,
        EntityRelation.predicate == predicate,
        EntityRelation.object_type == object_type,
        EntityRelation.object_id == object_id,
    )
    return session.scalar(statement) is not None
