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


def test_detector_phishing(detector):
    # High severity trigger: IP URL
    email_input = EmailInput(
        subject="Urgent",
        sender="attacker@10.0.0.1",
        body="Click here: http://10.0.0.1/login",
    )
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.PHISHING


def test_detector_suspicious(detector):
    # 2 Medium triggers: Urgency + Uppercase Subject (assuming > 10 chars)
    email_input = EmailInput(
        subject="URGENT ACTION REQUIRED NOW",
        sender="store@example.com",
        body="Please verify account immediately.",
    )
    result = detector.scan(email_input)

    assert result.classification == ClassificationType.SUSPICIOUS
