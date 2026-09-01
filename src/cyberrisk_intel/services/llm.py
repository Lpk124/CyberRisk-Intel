from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import requests

from cyberrisk_intel.config import settings


class OpenAICompatibleClient:
    """Minimal optional client; the application remains fully usable without it."""

    @property
    def enabled(self) -> bool:
        return bool(settings.llm_base_url and settings.llm_api_key)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            raise RuntimeError("Set CYBERRISK_LLM_BASE_URL and CYBERRISK_LLM_API_KEY first")
        assert settings.llm_base_url is not None
        response = requests.post(
            f"{settings.llm_base_url.rstrip('/')}/{path.lstrip('/')}",
            headers={"Authorization": f"Bearer {settings.llm_api_key}"},
            json=payload,
            timeout=settings.request_timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        data = self._post("embeddings", {"model": settings.embedding_model, "input": list(texts)})
        return [item["embedding"] for item in sorted(data["data"], key=lambda item: item["index"])]

    def answer(self, system: str, user: str) -> str:
        data = self._post(
            "chat/completions",
            {
                "model": settings.llm_model,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return str(data["choices"][0]["message"]["content"])
