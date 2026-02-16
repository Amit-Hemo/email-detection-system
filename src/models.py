from enum import StrEnum

from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    subject: str
    sender: str
    body: str


class ParsedEmail(BaseModel):
    sender_email: str
    sender_domain: str
    display_name: str
    urls: list[str] = Field(default_factory=list)
    normalized_body: str
    subject: str


class ClassificationType(StrEnum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    PHISHING = "Phishing"


class Severity(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class RuleResult(BaseModel):
    rule_name: str
    score: float = 0.0
    severity: Severity = Severity.LOW
    description: str
    triggered: bool


class ModelResult(BaseModel):
    classification: ClassificationType
    confidence_score: float


class ScanResult(BaseModel):
    classification: ClassificationType
    confidence_score: float
