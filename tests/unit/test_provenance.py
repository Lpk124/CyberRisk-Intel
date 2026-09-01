from hashlib import sha256

from sqlalchemy import func, select

from cyberrisk_intel.db.models import RawDocument
from cyberrisk_intel.ingestion.http import Download
from cyberrisk_intel.ingestion.provenance import record_download


def test_record_download_is_content_addressed(session, tmp_path, monkeypatch) -> None:
    import cyberrisk_intel.ingestion.provenance as provenance

    monkeypatch.setattr(provenance, "PROJECT_ROOT", tmp_path)
    content = b'{"status":"verified"}'
    item = Download(
        url="https://example.test/feed.json",
        content=content,
        content_type="application/json",
        sha256=sha256(content).hexdigest(),
    )
    first_source, first_document = record_download(
        session,
        item,
        source_name="Test feed",
        publisher="Test publisher",
        source_type="test-feed",
        region="Global",
    )
    second_source, second_document = record_download(
        session,
        item,
        source_name="Test feed",
        publisher="Test publisher",
        source_type="test-feed",
        region="Global",
    )
    session.flush()

    assert first_source.id == second_source.id
    assert first_document.id == second_document.id
    assert session.scalar(select(func.count()).select_from(RawDocument)) == 1
    assert (tmp_path / first_document.snapshot_path).read_bytes() == content
