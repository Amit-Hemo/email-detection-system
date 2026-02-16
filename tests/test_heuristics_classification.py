import pytest

from detection.heuristics import HeuristicModel
from models import ClassificationType, RuleResult, Severity


@pytest.fixture
def model():
    return HeuristicModel()


def create_result(severity: Severity, triggered: bool = True):
    return RuleResult(
        rule_name="Test Rule",
        score=1.0,
        severity=severity,
        description="Test description",
        triggered=triggered,
    )


def test_classify_phishing(model):
    # 1 High severity trigger
    results = [
        create_result(Severity.HIGH, triggered=True),
        create_result(Severity.LOW, triggered=True),
    ]
    assert model._resolve_classification(results) == ClassificationType.PHISHING


def test_classify_suspicious(model):
    # 2 Medium severity triggers
    results = [
        create_result(Severity.MEDIUM, triggered=True),
        create_result(Severity.MEDIUM, triggered=True),
        create_result(Severity.LOW, triggered=False),
    ]
    assert model._resolve_classification(results) == ClassificationType.SUSPICIOUS


def test_classify_safe_single_medium(model):
    # 1 Medium severity trigger -> Safe (per current logic)
    results = [create_result(Severity.MEDIUM, triggered=True)]
    assert model._resolve_classification(results) == ClassificationType.SAFE


def test_classify_safe_low_only(model):
    # Only low severity triggers -> Safe
    results = [
        create_result(Severity.LOW, triggered=True),
        create_result(Severity.LOW, triggered=True),
    ]
    assert model._resolve_classification(results) == ClassificationType.SAFE
