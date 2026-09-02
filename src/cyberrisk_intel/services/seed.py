from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberrisk_intel.config import PROJECT_ROOT
from cyberrisk_intel.db.models import (
    AttackTechnique,
    Control,
    ControlCatalog,
    DemoScenario,
    EntityRelation,
    EventSource,
    Industry,
    Policy,
    PolicyVersion,
    RiskTheme,
    ScenarioAsset,
    ScenarioRisk,
    SecurityEvent,
    ThreatPattern,
    Vulnerability,
)
from cyberrisk_intel.db.repository import get_or_create_source, json_dump, relation_exists
from cyberrisk_intel.domain.schemas import (
    AttackTechniqueInput,
    EventInput,
    PolicyInput,
    VulnerabilityInput,
)
from cyberrisk_intel.services.risk import risk_level

DEMO_DIR = PROJECT_ROOT / "data" / "demo"
TAXONOMY_DIR = PROJECT_ROOT / "data" / "taxonomies"


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _get_by_name(session: Session, model: type[Any], name: str) -> Any:
    result = session.scalar(select(model).where(model.name == name))
    if result is None:
        raise KeyError(f"Missing {model.__name__}: {name}")
    return result


def _add_relation(
    session: Session,
    *,
    subject_type: str,
    subject_id: str,
    predicate: str,
    object_type: str,
    object_id: str,
    evidence: str,
    source_id: str | None = None,
) -> None:
    pending_duplicate = any(
        isinstance(item, EntityRelation)
        and item.subject_type == subject_type
        and item.subject_id == subject_id
        and item.predicate == predicate
        and item.object_type == object_type
        and item.object_id == object_id
        for item in session.new
    )
    if pending_duplicate:
        return
    if relation_exists(session, subject_type, subject_id, predicate, object_type, object_id):
        return
    session.add(
        EntityRelation(
            subject_type=subject_type,
            subject_id=subject_id,
            predicate=predicate,
            object_type=object_type,
            object_id=object_id,
            evidence_excerpt=evidence,
            source_id=source_id,
            confidence="high",
            created_by="import",
            review_status="published",
        )
    )


def seed_taxonomies(session: Session) -> None:
    for row in _read_json(TAXONOMY_DIR / "industries.json"):
        if session.scalar(select(Industry).where(Industry.code == row["code"])) is None:
            session.add(Industry(**row))
    for row in _read_json(TAXONOMY_DIR / "threat_patterns.json"):
        if session.scalar(select(ThreatPattern).where(ThreatPattern.code == row["code"])) is None:
            session.add(ThreatPattern(**row))
    for row in _read_json(TAXONOMY_DIR / "risk_themes.json"):
        if session.scalar(select(RiskTheme).where(RiskTheme.code == row["code"])) is None:
            session.add(
                RiskTheme(
                    code=row["code"],
                    name=row["name"],
                    description=row["description"],
                    impact_dimensions_json=json_dump(row["impact_dimensions"]),
                )
            )
    session.flush()


def seed_controls(session: Session) -> None:
    data = _read_json(DEMO_DIR / "controls.json")
    catalog_data = data["catalog"]
    catalog = session.scalar(
        select(ControlCatalog).where(ControlCatalog.name == catalog_data["name"])
    )
    if catalog is None:
        catalog = ControlCatalog(**catalog_data)
        session.add(catalog)
        session.flush()
    for row in data["controls"]:
        if session.scalar(select(Control).where(Control.external_id == row["external_id"])):
            continue
        session.add(
            Control(
                catalog_id=catalog.id,
                source_url=catalog.source_url,
                review_status="published",
                **row,
            )
        )
    session.flush()


def seed_attack_techniques(session: Session) -> None:
    for raw in _read_json(DEMO_DIR / "attack_techniques.json"):
        item = AttackTechniqueInput.model_validate(raw)
        if session.scalar(
            select(AttackTechnique).where(AttackTechnique.attack_id == item.attack_id)
        ):
            continue
        session.add(
            AttackTechnique(
                attack_id=item.attack_id,
                name=item.name,
                description=item.description,
                tactics_json=json_dump(item.tactics),
                platforms_json=json_dump(item.platforms),
                version=item.version,
                revoked=item.revoked,
                source_url=str(item.source_url) if item.source_url else None,
                review_status="published",
            )
        )
    session.flush()


def seed_vulnerabilities(session: Session) -> None:
    for raw in _read_json(DEMO_DIR / "vulnerabilities.json"):
        item = VulnerabilityInput.model_validate(raw)
        if session.scalar(select(Vulnerability).where(Vulnerability.cve_id == item.cve_id)):
            continue
        session.add(
            Vulnerability(
                cve_id=item.cve_id,
                description=item.description,
                published_date=item.published_date,
                updated_date=item.updated_date,
                cvss_score=item.cvss_score,
                cvss_severity=item.cvss_severity.value,
                cwe_ids_json=json_dump(item.cwe_ids),
                affected_products_json=json_dump(item.affected_products),
                is_kev=item.is_kev,
                known_ransomware_use=item.known_ransomware_use,
                required_action=item.required_action,
                due_date=item.due_date,
                source_url=str(item.source_url) if item.source_url else None,
                review_status="published",
            )
        )
    session.flush()


POLICY_RISK_MAP = {
    "网络安全": ["治理与响应不足", "漏洞利用"],
    "数据安全": ["数据泄露与暴露", "治理与响应不足"],
    "个人信息保护": ["个人信息与隐私风险", "数据泄露与暴露"],
    "数据跨境": ["数据泄露与暴露", "个人信息与隐私风险"],
    "AI治理": ["AI与模型风险", "个人信息与隐私风险"],
    "供应链": ["供应链风险"],
    "事件响应": ["治理与响应不足", "服务可用性风险"],
}

POLICY_CONTROL_MAP = {
    "网络安全": ["CGI-GV-01", "CGI-ID-01", "CGI-RS-01"],
    "数据安全": ["CGI-ID-01", "CGI-PR-03", "CGI-DE-01"],
    "个人信息保护": ["CGI-PR-03", "CGI-GV-01"],
    "AI治理": ["CGI-GV-01", "CGI-GV-02", "CGI-PR-03"],
    "供应链": ["CGI-GV-02", "CGI-PR-04", "CGI-DE-02"],
    "事件响应": ["CGI-RS-01", "CGI-RC-02"],
}


def seed_policies(session: Session) -> None:
    for raw in _read_json(DEMO_DIR / "policies.json"):
        item = PolicyInput.model_validate(raw)
        policy = session.scalar(select(Policy).where(Policy.external_id == item.external_id))
        source = get_or_create_source(
            session,
            name=item.source.name,
            url=str(item.source.url),
            publisher=item.source.publisher,
            source_type=item.source.source_type,
            region=item.source.region,
            reliability=item.source.reliability.value,
            license_name=item.source.license_name,
        )
        if policy is None:
            policy = Policy(
                external_id=item.external_id,
                title=item.title,
                issuer=item.issuer,
                document_type=item.document_type.value,
                jurisdiction=item.jurisdiction,
                published_date=item.published_date,
                effective_date=item.effective_date,
                summary=item.summary,
                topics_json=json_dump(item.topics),
                review_status=item.status.value,
                source_id=source.id,
            )
            session.add(policy)
            session.flush()
            session.add(
                PolicyVersion(
                    policy_id=policy.id,
                    version_label="demo-summary-v1",
                    content_hash=_sha256(item.summary),
                    full_text=item.summary,
                    valid_from=item.effective_date,
                )
            )
        else:
            policy.title = item.title
            policy.issuer = item.issuer
            policy.document_type = item.document_type.value
            policy.jurisdiction = item.jurisdiction
            policy.published_date = item.published_date
            policy.effective_date = item.effective_date
            policy.summary = item.summary
            policy.topics_json = json_dump(item.topics)
            policy.review_status = item.status.value
            policy.source_id = source.id
        for topic in item.topics:
            for risk_name in POLICY_RISK_MAP.get(topic, []):
                risk = _get_by_name(session, RiskTheme, risk_name)
                _add_relation(
                    session,
                    subject_type="policy",
                    subject_id=policy.id,
                    predicate="addresses",
                    object_type="risk_theme",
                    object_id=risk.id,
                    evidence=(
                        f"Policy topic '{topic}' is explicitly assigned in the reviewed "
                        "demo metadata."
                    ),
                    source_id=source.id,
                )
            for control_id in POLICY_CONTROL_MAP.get(topic, []):
                control = session.scalar(select(Control).where(Control.external_id == control_id))
                if control:
                    _add_relation(
                        session,
                        subject_type="policy",
                        subject_id=policy.id,
                        predicate="supports",
                        object_type="control",
                        object_id=control.id,
                        evidence=f"Reviewed analytical mapping from policy topic '{topic}'.",
                        source_id=source.id,
                    )
    session.flush()


def seed_events(session: Session) -> None:
    for raw in _read_json(DEMO_DIR / "events.json"):
        item = EventInput.model_validate(raw)
        event = session.scalar(
            select(SecurityEvent).where(SecurityEvent.external_id == item.external_id)
        )
        industry = _get_by_name(session, Industry, item.industry)
        if event is None:
            event = SecurityEvent(
                external_id=item.external_id,
                title=item.title,
                title_zh=item.title_zh,
                summary=item.summary,
                summary_zh=item.summary_zh,
                incident_date=item.incident_date,
                incident_end_date=item.incident_end_date,
                disclosed_date=item.disclosed_date,
                region=item.region,
                organization=item.organization,
                organization_type=item.organization_type,
                industry_id=industry.id,
                root_cause=item.root_cause,
                affected_assets_json=json_dump(item.affected_assets),
                affected_data_json=json_dump(item.affected_data),
                impact=item.impact,
                source_severity=item.severity.value,
                normalized_severity=item.severity.value,
                confidence=item.confidence.value,
                review_status=item.status.value,
            )
            session.add(event)
            session.flush()

        primary_source_id: str | None = None
        for index, source_input in enumerate(item.sources):
            source = get_or_create_source(
                session,
                name=source_input.name,
                url=str(source_input.url),
                publisher=source_input.publisher,
                source_type=source_input.source_type,
                region=source_input.region,
                reliability=source_input.reliability.value,
                license_name=source_input.license_name,
            )
            primary_source_id = primary_source_id or source.id
            if session.get(EventSource, {"event_id": event.id, "source_id": source.id}) is None:
                session.add(
                    EventSource(
                        event_id=event.id,
                        source_id=source.id,
                        evidence_excerpt=item.summary,
                        is_primary=index == 0,
                    )
                )

        _add_relation(
            session,
            subject_type="security_event",
            subject_id=event.id,
            predicate="affects",
            object_type="industry",
            object_id=industry.id,
            evidence=f"Reviewed industry classification: {industry.name}.",
            source_id=primary_source_id,
        )
        for name in item.threat_patterns:
            threat = _get_by_name(session, ThreatPattern, name)
            _add_relation(
                session,
                subject_type="security_event",
                subject_id=event.id,
                predicate="uses_or_represents",
                object_type="threat_pattern",
                object_id=threat.id,
                evidence=item.summary,
                source_id=primary_source_id,
            )
        for name in item.risk_themes:
            risk = _get_by_name(session, RiskTheme, name)
            _add_relation(
                session,
                subject_type="security_event",
                subject_id=event.id,
                predicate="materializes",
                object_type="risk_theme",
                object_id=risk.id,
                evidence=item.impact or item.summary,
                source_id=primary_source_id,
            )
        for cve_id in item.cve_ids:
            vulnerability = session.scalar(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
            if vulnerability:
                _add_relation(
                    session,
                    subject_type="security_event",
                    subject_id=event.id,
                    predicate="exploits_or_involves",
                    object_type="vulnerability",
                    object_id=vulnerability.id,
                    evidence=item.root_cause or item.summary,
                    source_id=primary_source_id,
                )
        for attack_id in item.attack_ids:
            technique = session.scalar(
                select(AttackTechnique).where(AttackTechnique.attack_id == attack_id)
            )
            if technique:
                _add_relation(
                    session,
                    subject_type="security_event",
                    subject_id=event.id,
                    predicate="observed_technique",
                    object_type="attack_technique",
                    object_id=technique.id,
                    evidence=item.root_cause or item.summary,
                    source_id=primary_source_id,
                )
        for external_id in item.controls:
            control = session.scalar(select(Control).where(Control.external_id == external_id))
            if control:
                _add_relation(
                    session,
                    subject_type="security_event",
                    subject_id=event.id,
                    predicate="mitigated_by",
                    object_type="control",
                    object_id=control.id,
                    evidence=f"Analyst-reviewed control recommendation for {event.title}.",
                    source_id=primary_source_id,
                )
    session.flush()


def seed_risk_control_relations(session: Session) -> None:
    mapping = {
        "数据泄露与暴露": ["CGI-PR-03", "CGI-DE-01", "CGI-RS-01"],
        "身份与凭证滥用": ["CGI-PR-01", "CGI-RS-02", "CGI-DE-01"],
        "供应链风险": ["CGI-GV-02", "CGI-PR-04", "CGI-DE-02"],
        "勒索与破坏": ["CGI-PR-01", "CGI-RC-01", "CGI-RS-01"],
        "漏洞利用": ["CGI-ID-02", "CGI-PR-02", "CGI-DE-01"],
        "API与接口风险": ["CGI-PR-05", "CGI-DE-01"],
        "AI与模型风险": ["CGI-GV-02", "CGI-PR-03", "CGI-DE-01"],
        "个人信息与隐私风险": ["CGI-PR-03", "CGI-GV-01"],
        "服务可用性风险": ["CGI-RC-01", "CGI-RS-01"],
        "治理与响应不足": ["CGI-GV-01", "CGI-RS-01", "CGI-RC-02"],
    }
    for risk_name, control_ids in mapping.items():
        risk = _get_by_name(session, RiskTheme, risk_name)
        for external_id in control_ids:
            control = session.scalar(select(Control).where(Control.external_id == external_id))
            if control:
                _add_relation(
                    session,
                    subject_type="risk_theme",
                    subject_id=risk.id,
                    predicate="mitigated_by",
                    object_type="control",
                    object_id=control.id,
                    evidence="Reviewed baseline control mapping.",
                )


def seed_scenarios(session: Session) -> None:
    scenarios: list[
        tuple[str, str, str, list[tuple[str, str, str]], list[tuple[str, int, int]]]
    ] = [
        (
            "AI客服",
            "客服对话包含手机号、订单和问题描述，并调用第三方模型API。",
            "用户 → 客服系统 → 脱敏网关 → 第三方模型API → 客服坐席",
            [("聊天记录", "personal_data", "high"), ("订单信息", "business_data", "high")],
            [("AI与模型风险", 2, 3), ("个人信息与隐私风险", 2, 3)],
        ),
        (
            "第三方SDK",
            "移动应用集成统计、推送和广告SDK。",
            "移动端 → 第三方SDK → 第三方服务端",
            [("设备标识", "personal_data", "medium"), ("行为日志", "telemetry", "medium")],
            [("供应链风险", 2, 3), ("个人信息与隐私风险", 2, 3)],
        ),
        (
            "账号体系",
            "面向互联网的统一注册、登录和会话管理服务。",
            "用户 → 身份服务 → 业务系统与第三方登录",
            [("账号凭证", "credential", "high"), ("会话令牌", "token", "high")],
            [("身份与凭证滥用", 3, 3), ("API与接口风险", 2, 3)],
        ),
    ]
    for name, description, data_flow, assets, risks in scenarios:
        scenario = session.scalar(select(DemoScenario).where(DemoScenario.name == name))
        if scenario is not None:
            continue
        scenario = DemoScenario(name=name, description=description, data_flow=data_flow)
        session.add(scenario)
        session.flush()
        for asset_name, asset_type, sensitivity in assets:
            session.add(
                ScenarioAsset(
                    scenario_id=scenario.id,
                    name=asset_name,
                    asset_type=asset_type,
                    sensitivity=sensitivity,
                )
            )
        for risk_name, likelihood, impact in risks:
            risk = _get_by_name(session, RiskTheme, risk_name)
            session.add(
                ScenarioRisk(
                    scenario_id=scenario.id,
                    risk_theme_id=risk.id,
                    likelihood=likelihood,
                    impact=impact,
                    current_level=risk_level(likelihood, impact),
                    residual_likelihood=max(1, likelihood - 1),
                    residual_impact=impact,
                    residual_level=risk_level(max(1, likelihood - 1), impact),
                    evidence_strength="medium",
                    rationale="演示风险估计，需结合实际架构、控制和证据复核。",
                )
            )


def seed_demo(session: Session) -> None:
    seed_taxonomies(session)
    seed_controls(session)
    seed_attack_techniques(session)
    seed_vulnerabilities(session)
    seed_policies(session)
    seed_events(session)
    seed_risk_control_relations(session)
    seed_scenarios(session)
