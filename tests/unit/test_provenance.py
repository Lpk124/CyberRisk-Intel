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
    assert first_document.snapshot_path.endswith(".json")


def test_record_download_preserves_html_extension(session, tmp_path, monkeypatch) -> None:
    import cyberrisk_intel.ingestion.provenance as provenance

    monkeypatch.setattr(provenance, "PROJECT_ROOT", tmp_path)
    content = b"<html><body>public report</body></html>"
    item = Download(
        url="https://example.test/report",
        content=content,
        content_type="text/html; charset=UTF-8",
        sha256=sha256(content).hexdigest(),
    )
    _, document = record_download(
        session,
        item,
        source_name="Test HTML report",
        publisher="Test publisher",
        source_type="test-html",
        region="Global",
    )
    session.flush()

    assert document.snapshot_path.endswith(".html")
    assert (tmp_path / document.snapshot_path).read_bytes() == content


def test_record_download_preserves_pdf_extension(session, tmp_path, monkeypatch) -> None:
    import cyberrisk_intel.ingestion.provenance as provenance

    monkeypatch.setattr(provenance, "PROJECT_ROOT", tmp_path)
    content = b"%PDF-1.7\n% test fixture"
    item = Download(
        url="https://example.test/report.pdf",
        content=content,
        content_type="application/pdf",
        sha256=sha256(content).hexdigest(),
    )
    _, document = record_download(
        session,
        item,
        source_name="Test PDF report",
        publisher="Test publisher",
        source_type="test-pdf",
        region="Global",
    )
    session.flush()

    assert document.snapshot_path.endswith(".pdf")
    assert (tmp_path / document.snapshot_path).read_bytes() == content
