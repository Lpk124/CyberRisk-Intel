from __future__ import annotations

import hashlib
from dataclasses import dataclass

import requests

from cyberrisk_intel.config import settings


@dataclass(frozen=True)
class Download:
    url: str
    content: bytes
    content_type: str
    sha256: str


def download(url: str) -> Download:
    if not url.startswith(("https://", "http://")):
        raise ValueError("Only HTTP(S) sources are allowed")
    response = requests.get(
        url,
        timeout=settings.request_timeout_seconds,
        headers={"User-Agent": "CyberRisk-Intel/0.1 research-client"},
        stream=True,
    )
    response.raise_for_status()
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(64 * 1024):
        size += len(chunk)
        if size > settings.max_download_bytes:
            raise ValueError(f"Download exceeds {settings.max_download_bytes} bytes")
        chunks.append(chunk)
    content = b"".join(chunks)
    return Download(
        url, content, response.headers.get("content-type", ""), hashlib.sha256(content).hexdigest()
    )
