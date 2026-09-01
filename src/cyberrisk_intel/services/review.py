from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import EntityRelation, ReviewRecord
from cyberrisk_intel.db.repository import ENTITY_MODELS


def pending_items(session: Session) -> list[tuple[str, Any]]:
    output: list[tuple[str, Any]] = []
    for entity_type, model in ENTITY_MODELS.items():
        if hasattr(model, "review_status"):
            output.extend(
                (entity_type, row)
                for row in session.scalars(
                    select(model).where(model.review_status == "pending_review")
                )
            )
    output.extend(
        ("relationship", row)
        for row in session.scalars(
            select(EntityRelation).where(EntityRelation.review_status == "pending_review")
        )
    )
    return output


def set_review_status(
    session: Session,
    entity_type: str,
    entity_id: str,
    new_status: str,
    *,
    comment: str = "",
    reviewer: str = "local-user",
) -> None:
    model = EntityRelation if entity_type == "relationship" else ENTITY_MODELS[entity_type]
    entity = session.get(model, entity_id)
    if entity is None or not hasattr(entity, "review_status"):
        raise KeyError(f"Reviewable entity not found: {entity_type}:{entity_id}")
    previous = entity.review_status
    entity.review_status = new_status
    session.add(
        ReviewRecord(
            entity_type=entity_type,
            entity_id=entity_id,
            previous_status=previous,
            new_status=new_status,
            comment=comment,
            reviewer=reviewer,
        )
    )
