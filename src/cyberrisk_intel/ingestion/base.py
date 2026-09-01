from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class IngestionStats:
    discovered: int = 0
    created: int = 0
    updated: int = 0
    failed: int = 0


class Adapter[T](Protocol):
    def discover(self) -> list[str]: ...
    def fetch(self, identifier: str) -> bytes: ...
    def parse(self, payload: bytes) -> list[T]: ...
