from enum import StrEnum


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    PENDING = "pending_review"
    PUBLISHED = "published"
    REJECTED = "rejected"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EntityType(StrEnum):
    POLICY = "policy"
    POLICY_CLAUSE = "policy_clause"
    EVENT = "security_event"
    VULNERABILITY = "vulnerability"
    ATTACK_TECHNIQUE = "attack_technique"
    RISK = "risk_theme"
    INDUSTRY = "industry"
    CONTROL = "control"
    THREAT_PATTERN = "threat_pattern"


class RelationCreator(StrEnum):
    RULE = "rule"
    IMPORT = "import"
    AI = "ai"
    HUMAN = "human"


class CSFFunction(StrEnum):
    GOVERN = "Govern"
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"
