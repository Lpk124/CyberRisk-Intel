from __future__ import annotations

from collections import deque

import networkx as nx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import EntityRelation
from cyberrisk_intel.db.repository import entity_label, get_entity


def neighborhood(
    session: Session, entity_type: str, entity_id: str, *, depth: int = 1, max_nodes: int = 100
) -> nx.DiGraph:
    depth = min(max(depth, 1), 2)
    graph = nx.DiGraph()
    queue: deque[tuple[str, str, int]] = deque([(entity_type, entity_id, 0)])
    seen = {(entity_type, entity_id)}
    root = get_entity(session, entity_type, entity_id)
    if root is None:
        return graph
    graph.add_node(
        f"{entity_type}:{entity_id}", entity_type=entity_type, label=entity_label(entity_type, root)
    )
    while queue and graph.number_of_nodes() < max_nodes:
        current_type, current_id, level = queue.popleft()
        if level >= depth:
            continue
        relations = session.scalars(
            select(EntityRelation).where(
                EntityRelation.review_status == "published",
                or_(
                    (EntityRelation.subject_type == current_type)
                    & (EntityRelation.subject_id == current_id),
                    (EntityRelation.object_type == current_type)
                    & (EntityRelation.object_id == current_id),
                ),
            )
        )
        for relation in relations:
            endpoints = [
                (relation.subject_type, relation.subject_id),
                (relation.object_type, relation.object_id),
            ]
            for node_type, node_id in endpoints:
                key = f"{node_type}:{node_id}"
                if key not in graph and graph.number_of_nodes() >= max_nodes:
                    continue
                entity = get_entity(session, node_type, node_id)
                graph.add_node(
                    key,
                    entity_type=node_type,
                    label=entity_label(node_type, entity) if entity else node_id,
                )
                if (node_type, node_id) not in seen:
                    seen.add((node_type, node_id))
                    queue.append((node_type, node_id, level + 1))
            graph.add_edge(
                f"{relation.subject_type}:{relation.subject_id}",
                f"{relation.object_type}:{relation.object_id}",
                predicate=relation.predicate,
                evidence=relation.evidence_excerpt,
                confidence=relation.confidence,
                relation_id=relation.id,
            )
    return graph
