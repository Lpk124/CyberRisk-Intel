from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "CYBERRISK_DATABASE_URL",
        f"sqlite:///{(PROJECT_ROOT / 'data' / 'cyberrisk.db').as_posix()}",
    )
    llm_base_url: str | None = os.getenv("CYBERRISK_LLM_BASE_URL")
    llm_api_key: str | None = os.getenv("CYBERRISK_LLM_API_KEY")
    llm_model: str = os.getenv("CYBERRISK_LLM_MODEL", "gpt-4.1-mini")
    embedding_model: str = os.getenv("CYBERRISK_EMBEDDING_MODEL", "text-embedding-3-small")
    request_timeout_seconds: int = int(os.getenv("CYBERRISK_HTTP_TIMEOUT", "30"))
    max_download_bytes: int = int(os.getenv("CYBERRISK_MAX_DOWNLOAD_BYTES", "100000000"))


settings = Settings()
