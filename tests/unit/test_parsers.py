from pathlib import Path

from sqlalchemy import func, select

from cyberrisk_intel.db.models import EventSource, SecurityEvent
from cyberrisk_intel.ingestion.attack.mitre import parse_attack_stix
from cyberrisk_intel.ingestion.event.california import (
    parse_california_breaches,
    sync_california_breaches,
)
from cyberrisk_intel.ingestion.event.hhs import parse_hhs_breaches, sync_hhs_breaches
from cyberrisk_intel.ingestion.event.massachusetts import (
    parse_massachusetts_report_text,
    sync_massachusetts_breaches,
)
from cyberrisk_intel.ingestion.event.washington import (
    parse_washington_breaches,
    sync_washington_breaches,
)
from cyberrisk_intel.ingestion.vulnerability.cve import parse_cve_v5
from cyberrisk_intel.ingestion.vulnerability.kev import parse_kev
from cyberrisk_intel.services.seed import seed_taxonomies

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_parse_kev() -> None:
    rows = parse_kev((FIXTURES / "kev.json").read_bytes())
    assert rows[0]["cve_id"] == "CVE-2021-44228"
    assert rows[0]["known_ransomware_use"] is True


def test_parse_cve_v5_with_cna_and_adp() -> None:
    item = parse_cve_v5((FIXTURES / "cve.json").read_bytes())
    assert item.cve_id == "CVE-2024-9999"
    assert item.cvss_score == 7.5
    assert item.cwe_ids == ["CWE-79"]
    assert item.affected_products == ["Example / Widget"]


def test_parse_attack_stix() -> None:
    tactics, techniques = parse_attack_stix((FIXTURES / "attack.json").read_bytes())
    assert tactics[0]["attack_id"] == "TA0001"
    assert techniques[0]["attack_id"] == "T1190"
    assert techniques[0]["tactics"] == ["initial-access"]


def test_parse_hhs_breach_table() -> None:
    rows = parse_hhs_breaches((FIXTURES / "hhs_breaches.html").read_bytes())
    assert len(rows) == 2
    assert rows[0].covered_entity == "Example Medical Center"
    assert rows[0].individuals_affected == 12345
    assert rows[0].submission_date.isoformat() == "2026-08-01"
    assert rows[0].external_id == "HHS-OCR-1234567"


def test_sync_hhs_breaches_is_idempotent_and_preserves_unknown_date(session) -> None:
    seed_taxonomies(session)
    payload = (FIXTURES / "hhs_breaches.html").read_bytes()
    first = sync_hhs_breaches(session, payload, limit=2)
    second = sync_hhs_breaches(session, payload, limit=2)
    session.flush()

    assert first.created == 2
    assert second.updated == 2
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
    assert session.scalar(select(func.count()).select_from(EventSource)) == 2
    event = session.scalar(select(SecurityEvent).order_by(SecurityEvent.disclosed_date.desc()))
    assert event is not None
    assert event.incident_date is None
    assert event.disclosed_date is not None
    assert event.review_status == "pending_review"


def test_sync_hhs_migrates_legacy_hash_to_official_row_id(session) -> None:
    seed_taxonomies(session)
    payload = (FIXTURES / "hhs_breaches.html").read_bytes()
    legacy_payload = payload.replace(b' data-rk="1234567"', b"").replace(
        b' data-rk="1234568"', b""
    )
    sync_hhs_breaches(session, legacy_payload, limit=2)
    sync_hhs_breaches(session, payload, limit=2)
    session.flush()

    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
    external_ids = set(session.scalars(select(SecurityEvent.external_id)))
    assert external_ids == {"HHS-OCR-1234567", "HHS-OCR-1234568"}


def test_parse_california_breach_csv_preserves_date_range() -> None:
    rows = parse_california_breaches((FIXTURES / "california_breaches.csv").read_bytes())
    assert len(rows) == 2
    assert rows[0].organization == "Example Retailer"
    assert rows[0].incident_start is not None
    assert rows[0].incident_start.isoformat() == "2026-05-01"
    assert rows[0].incident_end is not None
    assert rows[0].incident_end.isoformat() == "2026-05-03"
    assert rows[1].incident_start is None


def test_sync_california_breaches_is_idempotent(session) -> None:
    seed_taxonomies(session)
    payload = (FIXTURES / "california_breaches.csv").read_bytes()
    first = sync_california_breaches(session, payload, limit=2)
    second = sync_california_breaches(session, payload, limit=2)
    session.flush()

    assert first.created == 2
    assert second.updated == 2
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
    event = session.scalar(
        select(SecurityEvent).where(SecurityEvent.incident_end_date.is_not(None))
    )
    assert event is not None
    assert event.organization_type == "notifying_organization"
    assert event.review_status == "pending_review"


def test_parse_massachusetts_report_skips_wrapped_rows() -> None:
    text = (FIXTURES / "massachusetts_breaches.txt").read_text(encoding="utf-8")
    rows = parse_massachusetts_report_text(text)

    assert [row.external_id for row in rows] == [
        "MA-OCABR-2026-1",
        "MA-OCABR-2026-3",
    ]
    assert rows[0].organization == "Example Technology LLC"
    assert rows[0].residents_affected == 1200
    assert rows[0].affected_data == (
        "Social Security number",
        "financial account information",
    )


def test_sync_massachusetts_breaches_is_idempotent(session) -> None:
    seed_taxonomies(session)
    text = (FIXTURES / "massachusetts_breaches.txt").read_text(encoding="utf-8")
    first = sync_massachusetts_breaches(session, extracted_text=text, limit=2)
    second = sync_massachusetts_breaches(session, extracted_text=text, limit=2)
    session.flush()

    assert first.created == 2
    assert second.updated == 2
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
    event = session.scalar(
        select(SecurityEvent).where(SecurityEvent.external_id == "MA-OCABR-2026-1")
    )
    assert event is not None
    assert event.incident_date is None
    assert event.disclosed_date is not None
    assert event.affected_data_json != "[]"
    assert event.review_status == "pending_review"


def test_parse_washington_breaches_joins_personal_information() -> None:
    rows = parse_washington_breaches(
        (FIXTURES / "washington_breaches.csv").read_bytes(),
        (FIXTURES / "washington_personal_info.csv").read_bytes(),
    )

    assert rows[0].external_id == "WA-AGO-25260"
    assert rows[0].organization == "Example Retail LLC"
    assert rows[0].incident_start is not None
    assert rows[0].affected_data == ("Name", "Social Security Number")


def test_sync_washington_breaches_is_idempotent(session) -> None:
    seed_taxonomies(session)
    main = (FIXTURES / "washington_breaches.csv").read_bytes()
    detail = (FIXTURES / "washington_personal_info.csv").read_bytes()
    first = sync_washington_breaches(session, main, detail, limit=2)
    second = sync_washington_breaches(session, main, detail, limit=2)
    session.flush()

    assert first.created == 2
    assert second.updated == 2
    assert session.scalar(select(func.count()).select_from(SecurityEvent)) == 2
    assert session.scalar(select(func.count()).select_from(EventSource)) == 4
    event = session.scalar(
        select(SecurityEvent).where(SecurityEvent.external_id == "WA-AGO-25260")
    )
    assert event is not None
    assert event.incident_end_date is not None
    assert event.disclosed_date is not None
    assert event.review_status == "pending_review"
