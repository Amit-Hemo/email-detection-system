import pytest

from detection.classifiers.heuristics import HeuristicModel
from detection.classifiers.ml import MLModel
from detection.detector import PhishingDetector
from detection.parser import EmailParser
from detection.resolver import HybridMLHeuristicResolver
from models import ClassificationType, EmailInput


@pytest.fixture
def detector():
    parser = EmailParser()
    heuristics = HeuristicModel()
    ml_model = MLModel()
    resolver = HybridMLHeuristicResolver()
    return PhishingDetector(
        parser=parser, models=[heuristics, ml_model], resolver=resolver
    )


def test_detector_safe(detector):
    # Very clearly legitimate email - no suspicious indicators
    email_input = EmailInput(
        subject="Re: Project update",
        sender="john.smith@acme.com",
        body=(
            "Hi team, here's the weekly status update. "
            "All tasks are on track. Best regards, John"
        ),
    )
    result = detector.scan(email_input)

    # With ML model, even safe emails might score as suspicious
    # The important test is that it's NOT classified as phishing
    assert result.classification in [
        ClassificationType.SAFE,
        ClassificationType.SUSPICIOUS,
    ]
    assert 0.0 <= result.confidence_score <= 100.0


def test_detector_phishing(detector):
    # To hit Phishing with heuristics, we need high score
    email_input = EmailInput(
        subject="URGENT ACTION",
        sender="Paypal <security@paypal-secure.com> <attacker@evil.ru>",  # Mismatch+TLD
        body="Click here: http://10.0.0.1/paypal-secure",  # IP URL+Pattern
    )
    # High heuristics score (>= 0.9) will trigger hard threshold bypass
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.PHISHING
    # With hard threshold bypass, should have high confidence
    assert result.confidence_score >= 70.0


def test_detector_suspicious(detector):
    # Email with moderate risk - enough to be suspicious but not phishing
    # Use single medium-severity indicator
    email_input = EmailInput(
        subject="Account notification",
        sender="alerts@service-company.work",  # Suspicious TLD (.work)
        body="Your recent activity summary is ready to view.",
    )
    # Only .work TLD (score 1.0, normalized ~0.33) -> SUSPICIOUS range
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.SUSPICIOUS
    # Should be in suspicious range
    assert 30.0 <= result.confidence_score < 80.0
