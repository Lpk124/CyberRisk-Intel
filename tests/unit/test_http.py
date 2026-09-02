from __future__ import annotations

import requests

from cyberrisk_intel.ingestion.http import download


class _Response:
    status_code = 200
    headers = {"content-type": "text/csv"}

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, _size: int):
        yield b"header\nvalue\n"


def test_download_retries_transient_transport_error(monkeypatch) -> None:
    attempts = 0

    def fake_get(*_args: object, **_kwargs: object) -> _Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise requests.exceptions.SSLError("temporary EOF")
        return _Response()

    monkeypatch.setattr("cyberrisk_intel.ingestion.http.requests.get", fake_get)
    monkeypatch.setattr("cyberrisk_intel.ingestion.http.time.sleep", lambda _seconds: None)

    result = download("https://example.test/data.csv")

    assert attempts == 2
    assert result.content == b"header\nvalue\n"
    assert result.content_type == "text/csv"
