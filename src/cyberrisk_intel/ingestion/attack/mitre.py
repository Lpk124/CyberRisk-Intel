from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.db.models import AttackTactic, AttackTechnique, IngestionRun
from cyberrisk_intel.db.repository import json_dump
from cyberrisk_intel.ingestion.base import IngestionStats
from cyberrisk_intel.ingestion.http import download
from cyberrisk_intel.ingestion.provenance import record_download

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def _external_id(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def parse_attack_stix(payload: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bundle = json.loads(payload.decode("utf-8-sig"))
    tactics: list[dict[str, Any]] = []
    techniques: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        external_id, source_url = _external_id(obj)
        if obj.get("type") == "x-mitre-tactic" and external_id:
            tactics.append(
                {
                    "attack_id": external_id,
                    "name": obj.get("name", external_id),
                    "description": obj.get("description", ""),
                }
            )
        elif obj.get("type") == "attack-pattern" and external_id and external_id.startswith("T"):
            techniques.append(
                {
                    "attack_id": external_id,
                    "name": obj.get("name", external_id),
                    "description": obj.get("description", ""),
                    "tactics": [
                        phase["phase_name"]
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ],
                    "platforms": obj.get("x_mitre_platforms", []),
                    "version": obj.get("x_mitre_version"),
                    "revoked": bool(obj.get("revoked") or obj.get("x_mitre_deprecated")),
                    "source_url": source_url,
                }
            )
    return tactics, techniques


def sync_attack(session: Session, payload: bytes | None = None) -> IngestionStats:
    run = IngestionRun(adapter="mitre-enterprise-attack")
    session.add(run)
    payload_data = payload
    if payload_data is None:
        downloaded = download(ATTACK_STIX_URL)
        record_download(
            session,
            downloaded,
            source_name="MITRE Enterprise ATT&CK STIX 2.1",
            publisher="MITRE",
            source_type="mitre-attack",
            region="Global",
            license_name="MITRE ATT&CK Terms of Use",
        )
        payload_data = downloaded.content
    tactics, techniques = parse_attack_stix(payload_data)
    created = updated = 0
    for item in tactics:
        tactic_row = session.scalar(
            select(AttackTactic).where(AttackTactic.attack_id == item["attack_id"])
        )
        if tactic_row is None:
            session.add(AttackTactic(**item))
            created += 1
        else:
            tactic_row.name = item["name"]
            tactic_row.description = item["description"]
            updated += 1
    for item in techniques:
        technique_row = session.scalar(
            select(AttackTechnique).where(AttackTechnique.attack_id == item["attack_id"])
        )
        if technique_row is None:
            technique_row = AttackTechnique(
                attack_id=item["attack_id"], name=item["name"], description=item["description"]
            )
            session.add(technique_row)
            created += 1
        else:
            updated += 1
        technique_row.name = item["name"]
        technique_row.description = item["description"]
        technique_row.tactics_json = json_dump(item["tactics"])
        technique_row.platforms_json = json_dump(item["platforms"])
        technique_row.version = item["version"]
        technique_row.revoked = item["revoked"]
        technique_row.source_url = item["source_url"]
        technique_row.review_status = "published"
    run.discovered = len(tactics) + len(techniques)
    run.created = created
    run.updated = updated
    run.status = "completed"
    run.finished_at = datetime.now(UTC)
    return IngestionStats(len(tactics) + len(techniques), created, updated, 0)
