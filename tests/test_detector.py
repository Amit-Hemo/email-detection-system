import pytest

from detection.detector import PhishingDetector
from detection.heuristics import HeuristicModel
from detection.parser import EmailParser
from detection.resolver import SimpleResolver
from models import ClassificationType, EmailInput


@pytest.fixture
def detector():
    parser = EmailParser()
    heuristics = HeuristicModel()
    resolver = SimpleResolver()
    return PhishingDetector(parser=parser, models=[heuristics], resolver=resolver)


def test_detector_safe(detector):
    email_input = EmailInput(
        subject="Hello", sender="friend@example.com", body="Just saying hi."
    )
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.SAFE
    assert result.confidence_score == 0.0


def test_detector_phishing(detector):
    # To hit Phishing (0.7) with MAX_SCORE=3.0, we need score >= 2.1
    email_input = EmailInput(
        subject="URGENT ACTION",
        sender="Paypal <security@paypal-secure.com> <attacker@evil.ru>",  # Mismatch+TLD
        body="Click here: http://10.0.0.1/paypal-secure",  # IP URL+Pattern
    )
    # Score: 1.0(TLD) + 1.0(Mismatch) + 1.0(IP) + 1.0(Pattern) + 0.3(Upper) = 4.3
    # Normalized: min(4.3 / 3.0, 1.0) = 1.0
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.PHISHING
    assert result.confidence_score == 1.0


def test_detector_suspicious(detector):
    # To hit Suspicious (0.3) with MAX_SCORE=3.0, we need score >= 0.9
    email_input = EmailInput(
        subject="Action Required",
        sender="Admin <admin@company.com> <attacker@evil.com>",
        body="Please check your account settings now.",
    )
    # Score: 1.0 (Mismatch) + 0.5 (Urgency) = 1.5 -> Normalized 0.5
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.SUSPICIOUS
    assert result.confidence_score == 0.5
