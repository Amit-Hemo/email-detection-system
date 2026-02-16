from fastapi.testclient import TestClient

from api import app
from models import ClassificationType

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_analyze_email_safe():
    payload = {
        "subject": "Hello",
        "sender": "friend@example.com",
        "body": "Just checking in.",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationType.SAFE
    assert data["confidence_score"] == 0.0


def test_analyze_email_phishing():
    # To get PHISHING (>= 0.7), we need score >= 2.1 (with MAX_SCORE=3.0)
    payload = {
        "subject": "URGENT ACTION REQUIRED",  # Uppercase + Urgency
        "sender": "attacker@evil.ru",  # Suspicious TLD
        "body": "Click: http://1.1.1.1/paypal-secure now",  # IP URL + Pattern + Urgency
    }
    # Total Score: 0.3 + 1.0 + 1.0 + 1.0 + 0.5 = 3.8
    # Normalized: min(3.8 / 3.0, 1.0) = 1.0

    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationType.PHISHING
    assert data["confidence_score"] == 1.0


def test_invalid_input():
    # Missing required field 'body'
    payload = {"subject": "Incomplete", "sender": "oops@example.com"}
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422
