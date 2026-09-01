from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.config import PROJECT_ROOT
from cyberrisk_intel.db.models import RawDocument, Source
from cyberrisk_intel.db.repository import get_or_create_source
from cyberrisk_intel.ingestion.http import Download


def record_download(
    session: Session,
    item: Download,
    *,
    source_name: str,
    publisher: str,
    source_type: str,
    region: str,
    reliability: str = "high",
    license_name: str | None = None,
) -> tuple[Source, RawDocument]:
    """Persist an immutable, content-addressed snapshot and its audit record."""
    source = get_or_create_source(
        session,
        name=source_name,
        url=item.url,
        publisher=publisher,
        source_type=source_type,
        region=region,
        reliability=reliability,
        license_name=license_name,
    )
    snapshot_path = (
        PROJECT_ROOT
        / "data"
        / "raw"
        / source_type
        / f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{item.sha256[:16]}.json"
    )
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    if not snapshot_path.exists():
        snapshot_path.write_bytes(item.content)
    document = session.scalar(
        select(RawDocument).where(
            RawDocument.original_url == item.url,
            RawDocument.content_hash == item.sha256,
        )
    )
    if document is None:
        document = RawDocument(
            source_id=source.id,
            original_url=item.url,
            content_hash=item.sha256,
            snapshot_path=str(snapshot_path.relative_to(PROJECT_ROOT)),
            parse_status="parsed",
        )
        session.add(document)
        session.flush()
    return source, document
