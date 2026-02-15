from detection.classifier import classify_email
from models import ClassificationType, RuleResult, Severity


def create_result(severity: Severity, triggered: bool = True):
    return RuleResult(
        rule_name="Test Rule",
        score=1.0,
        severity=severity,
        description="Test description",
        triggered=triggered,
    )


def test_classify_phishing():
    heuristics = [
        create_result(Severity.HIGH, triggered=True),
        create_result(Severity.LOW, triggered=True),
    ]
    assert classify_email(heuristics) == ClassificationType.PHISHING


def test_classify_suspicious():
    heuristics = [
        create_result(Severity.MEDIUM, triggered=True),
        create_result(Severity.MEDIUM, triggered=True),
        create_result(Severity.LOW, triggered=False),
    ]
    assert classify_email(heuristics) == ClassificationType.SUSPICIOUS


def test_classify_safe_single_medium():
    heuristics = [create_result(Severity.MEDIUM, triggered=True)]
    assert classify_email(heuristics) == ClassificationType.SAFE


def test_classify_safe_low_only():
    heuristics = [
        create_result(Severity.LOW, triggered=True),
        create_result(Severity.LOW, triggered=True),
    ]
    assert classify_email(heuristics) == ClassificationType.SAFE
