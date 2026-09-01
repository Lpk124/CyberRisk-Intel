from pathlib import Path

from sqlalchemy import func, select

from cyberrisk_intel.db.models import Policy, PolicyClause, SecurityEvent
from cyberrisk_intel.ingestion.importers import import_events, import_policies
from cyberrisk_intel.services.seed import seed_taxonomies

DEMO = Path(__file__).parents[2] / "data" / "demo"


def test_json_importers_are_idempotent(session) -> None:
    seed_taxonomies(session)
    first_policy = import_policies(session, DEMO / "policies.json")
    first_event = import_events(session, DEMO / "events.json")
    second_policy = import_policies(session, DEMO / "policies.json")
    second_event = import_events(session, DEMO / "events.json")
    session.flush()

    assert first_policy.created == 30
    assert first_event.created == 12
    assert second_policy.updated == 30
    assert second_event.updated == 12
    assert session.scalar(select(func.count()).select_from(Policy)) == 30
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 12
    assert session.scalar(select(func.count()).select_from(PolicyClause)) == 0
    document_types = set(session.scalars(select(Policy.document_type)))
    assert {
        "law",
        "administrative_regulation",
        "departmental_rule",
        "normative_document",
        "technical_framework",
    } <= document_types
