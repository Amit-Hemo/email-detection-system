import pytest

from detection.heuristics import HeuristicModel
from models import ClassificationType, ParsedEmail


@pytest.fixture
def model() -> HeuristicModel:
    return HeuristicModel()


def test_resolve_classification(model: HeuristicModel):
    # Phishing: score >= 0.7
    assert model._resolve_classification(0.7) == ClassificationType.PHISHING
    assert model._resolve_classification(1.0) == ClassificationType.PHISHING

    # Suspicious: 0.3 <= score < 0.7
    assert model._resolve_classification(0.3) == ClassificationType.SUSPICIOUS
    assert model._resolve_classification(0.5) == ClassificationType.SUSPICIOUS
    assert model._resolve_classification(0.69) == ClassificationType.SUSPICIOUS

    # Safe: score < 0.3
    assert model._resolve_classification(0.29) == ClassificationType.SAFE
    assert model._resolve_classification(0.0) == ClassificationType.SAFE


def test_classify_full_logic(model: HeuristicModel):
    # Extremely suspicious email to hit Phishing (>= 0.7)
    # Total score needed with MAX_SCORE=3.0: 2.1
    email = ParsedEmail(
        sender_email="attacker@evil.ru",  # Suspicious TLD
        sender_domain="evil.ru",
        display_name="PayPal Support <security@paypal-secure.com>",  # Display Mismatch
        urls=["http://1.1.1.1/paypal-secure"],  # IP URL + Phishing Pattern
        normalized_body="urgent account verify immediately",  # Urgency
        subject="URGENT SECURITY ALERT",  # Uppercase + Urgency
    )
    # Total score: 1.0 + 1.0 + 1.0 + 1.0 + 0.5 + 0.3 = 4.8
    # Normalized: min(4.8 / 3.0, 1.0) = 1.0

    result = model.classify(email)
    assert result.classification == ClassificationType.PHISHING
    assert result.confidence_score == 1.0

    # Safe email
    email_safe = ParsedEmail(
        sender_email="user@example.com",
        sender_domain="example.com",
        display_name="User",
        urls=[],
        normalized_body="just a friendly hello",
        subject="Hello",
    )
    result = model.classify(email_safe)
    assert result.classification == ClassificationType.SAFE
    assert result.confidence_score == 0.0
