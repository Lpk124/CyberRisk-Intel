from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import numpy as np
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import SearchChunk
from cyberrisk_intel.retrieval.index import tokenize


@dataclass(frozen=True)
class SearchResult:
    rank: int
    score: float
    entity_type: str
    entity_id: str
    title: str
    excerpt: str
    source_id: str | None
    published_at: object | None
    topics: tuple[str, ...]
    chunk_id: str


def _fts_query(value: str) -> str:
    tokens = [t for t in tokenize(value).split() if re.fullmatch(r"[\w.：:/-]+", t)]
    return " OR ".join(f'"{token.replace(chr(34), "")}"' for token in dict.fromkeys(tokens[:12]))


def _lexical(session: Session, query: str, limit: int) -> list[tuple[SearchChunk, float]]:
    fts_query = _fts_query(query)
    if not fts_query:
        return []
    rows = session.execute(
        text(
            "SELECT chunk_id, bm25(search_fts, 2.0, 1.0) AS score "
            "FROM search_fts WHERE search_fts MATCH :query ORDER BY score LIMIT :limit"
        ),
        {"query": fts_query, "limit": limit},
    ).all()
    by_id = (
        {
            chunk.id: chunk
            for chunk in session.scalars(
                select(SearchChunk).where(SearchChunk.id.in_([r[0] for r in rows]))
            )
        }
        if rows
        else {}
    )
    return [(by_id[row[0]], float(-row[1])) for row in rows if row[0] in by_id]


def _semantic(
    session: Session, query: str, embedder: Callable[[Sequence[str]], list[list[float]]], limit: int
) -> list[tuple[SearchChunk, float]]:
    query_vector = np.asarray(embedder([query])[0], dtype=float)
    query_norm = float(np.linalg.norm(query_vector))
    if query_norm == 0:
        return []
    scores: list[tuple[SearchChunk, float]] = []
    for chunk in session.scalars(
        select(SearchChunk).where(SearchChunk.embedding_json.is_not(None))
    ):
        vector = np.asarray(json.loads(chunk.embedding_json or "[]"), dtype=float)
        if vector.shape != query_vector.shape:
            continue
        denominator = query_norm * float(np.linalg.norm(vector))
        if denominator:
            scores.append((chunk, float(np.dot(query_vector, vector) / denominator)))
    return sorted(scores, key=lambda item: item[1], reverse=True)[:limit]


def hybrid_search(
    session: Session,
    query: str,
    *,
    entity_types: Sequence[str] | None = None,
    limit: int = 12,
    candidate_limit: int = 40,
    embedder: Callable[[Sequence[str]], list[list[float]]] | None = None,
) -> list[SearchResult]:
    """RRF fusion over FTS5 and optional embeddings, restricted to reviewed chunks."""
    lexical = _lexical(session, query, candidate_limit)
    semantic = _semantic(session, query, embedder, candidate_limit) if embedder else []
    allowed = set(entity_types or [])
    scores: dict[str, float] = {}
    chunks: dict[str, SearchChunk] = {}
    for result_set in (lexical, semantic):
        for position, (chunk, _) in enumerate(result_set, start=1):
            if chunk.review_status != "published" or (allowed and chunk.entity_type not in allowed):
                continue
            chunks[chunk.id] = chunk
            scores[chunk.id] = scores.get(chunk.id, 0.0) + 1.0 / (60 + position)
    ordered = sorted(scores, key=lambda chunk_id: scores[chunk_id], reverse=True)[:limit]
    return [
        SearchResult(
            rank=index,
            score=round(scores[chunk_id], 6),
            entity_type=chunks[chunk_id].entity_type,
            entity_id=chunks[chunk_id].entity_id,
            title=chunks[chunk_id].title,
            excerpt=chunks[chunk_id].body[:360],
            source_id=chunks[chunk_id].source_id,
            published_at=chunks[chunk_id].published_at,
            topics=tuple(json.loads(chunks[chunk_id].topics_json)),
            chunk_id=chunk_id,
        )
        for index, chunk_id in enumerate(ordered, start=1)
    ]
