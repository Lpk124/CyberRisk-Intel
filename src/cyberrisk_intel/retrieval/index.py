from __future__ import annotations

import json
import re
from dataclasses import dataclass

import jieba
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import (
    AttackTechnique,
    Control,
    Policy,
    RiskTheme,
    SearchChunk,
    SecurityEvent,
    Vulnerability,
)


@dataclass(frozen=True)
class IndexDocument:
    entity_type: str
    entity_id: str
    title: str
    body: str
    source_id: str | None = None
    published_at: object | None = None
    language: str = "zh"
    topics: tuple[str, ...] = ()
    review_status: str = "published"


def tokenize(text_value: str) -> str:
    """Create a stable mixed Chinese/Latin token stream for SQLite FTS5."""
    cleaned = re.sub(r"\s+", " ", text_value).strip()
    tokens = [token.strip().lower() for token in jieba.cut(cleaned) if token.strip()]
    latin = re.findall(r"[A-Za-z][A-Za-z0-9_.:/-]*|CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?", cleaned)
    return " ".join(tokens + [token.lower() for token in latin])


def _documents(session: Session) -> list[IndexDocument]:
    documents: list[IndexDocument] = []
    for policy in session.scalars(select(Policy).where(Policy.review_status == "published")):
        documents.append(
            IndexDocument(
                "policy",
                policy.id,
                policy.title,
                policy.summary,
                policy.source_id,
                policy.published_date,
                "zh",
                tuple(json.loads(policy.topics_json)),
            )
        )
    for event in session.scalars(
        select(SecurityEvent).where(SecurityEvent.review_status == "published")
    ):
        title = event.title_zh or event.title
        body = "\n".join(
            filter(None, [event.summary_zh, event.summary, event.root_cause, event.impact])
        )
        documents.append(
            IndexDocument(
                "security_event",
                event.id,
                title,
                body,
                None,
                event.incident_date or event.disclosed_date,
                "zh" if event.title_zh else "en",
            )
        )
    for vulnerability in session.scalars(
        select(Vulnerability).where(Vulnerability.review_status == "published")
    ):
        documents.append(
            IndexDocument(
                "vulnerability",
                vulnerability.id,
                vulnerability.cve_id,
                vulnerability.description,
                None,
                vulnerability.published_date,
                "en",
                ("KEV",) if vulnerability.is_kev else (),
            )
        )
    for technique in session.scalars(
        select(AttackTechnique).where(AttackTechnique.review_status == "published")
    ):
        documents.append(
            IndexDocument(
                "attack_technique",
                technique.id,
                f"{technique.attack_id} {technique.name}",
                technique.description,
                None,
                None,
                "en",
                tuple(json.loads(technique.tactics_json)),
            )
        )
    for risk in session.scalars(select(RiskTheme)):
        documents.append(IndexDocument("risk_theme", risk.id, risk.name, risk.description))
    for control in session.scalars(select(Control).where(Control.review_status == "published")):
        documents.append(
            IndexDocument(
                "control",
                control.id,
                f"{control.external_id} {control.title}",
                control.description,
                None,
                None,
                "zh",
                (control.csf_function,),
            )
        )
    return documents


def rebuild_index(session: Session) -> int:
    session.execute(delete(SearchChunk))
    session.execute(text("DELETE FROM search_fts"))
    session.flush()
    count = 0
    for document in _documents(session):
        chunk = SearchChunk(
            entity_type=document.entity_type,
            entity_id=document.entity_id,
            title=document.title,
            body=document.body,
            source_id=document.source_id,
            published_at=document.published_at,
            language=document.language,
            topics_json=json.dumps(document.topics, ensure_ascii=False),
            review_status=document.review_status,
            chunk_path="root",
        )
        session.add(chunk)
        session.flush()
        session.execute(
            text(
                "INSERT INTO search_fts(rowid, chunk_id, title, body) "
                "VALUES (:rowid,:id,:title,:body)"
            ),
            {
                "rowid": count + 1,
                "id": chunk.id,
                "title": tokenize(chunk.title),
                "body": tokenize(chunk.body),
            },
        )
        count += 1
    return count
