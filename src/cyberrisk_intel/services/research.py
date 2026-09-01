from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from cyberrisk_intel.retrieval.search import SearchResult, hybrid_search
from cyberrisk_intel.services.llm import OpenAICompatibleClient


@dataclass(frozen=True)
class ResearchAnswer:
    text: str
    results: tuple[SearchResult, ...]
    used_llm: bool
    citations_valid: bool


def _context(results: list[SearchResult]) -> str:
    return "\n\n".join(
        f"[{row.entity_type}:{row.entity_id}] {row.title}\n{row.excerpt}\n"
        f"source_id={row.source_id or 'none'}"
        for row in results
    )


def _valid_citations(answer: str, results: list[SearchResult]) -> bool:
    allowed = {f"{row.entity_type}:{row.entity_id}" for row in results}
    cited = set(re.findall(r"\[([a-z_]+:[0-9a-f-]+)\]", answer))
    return bool(cited) and cited <= allowed


def research(session: Session, question: str, *, use_llm: bool = False) -> ResearchAnswer:
    client = OpenAICompatibleClient()
    results = hybrid_search(session, question, embedder=client.embed if client.enabled else None)
    if not results:
        return ResearchAnswer("没有找到足够的已复核证据，无法形成结论。", (), False, True)
    if use_llm and client.enabled:
        answer = client.answer(
            "你是网络安全研究助手。只使用提供的证据；每项事实必须引用方括号中的实体ID。"
            "不得把相关性写成因果关系，不得引用上下文外的ID；证据不足时明确说明。",
            f"问题：{question}\n\n证据：\n{_context(results)}",
        )
        valid = _valid_citations(answer, results)
        if not valid:
            answer = "模型输出未通过引用校验，已拒绝发布。请查看下方检索证据。"
        return ResearchAnswer(answer, tuple(results), True, valid)
    bullets = "\n".join(
        f"- {row.title}：{row.excerpt[:180]} [{row.entity_type}:{row.entity_id}]"
        for row in results[:6]
    )
    return ResearchAnswer(
        "以下是与问题最相关的已复核情报，不代表因果判断：\n" + bullets,
        tuple(results),
        False,
        True,
    )
