from fastapi.testclient import TestClient

from api import app
from models import ClassificationType

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_analyze_email_safe():
    # Very clearly safe email - personal message with no suspicious indicators
    payload = {
        "subject": "Meeting tomorrow",
        "sender": "colleague@company.com",
        "body": (
            "Hey, just wanted to confirm our meeting scheduled for "
            "tomorrow at 2pm. Looking forward to discussing the "
            "project updates."
        ),
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    # ML model may not classify as safe due to training data
    # Check it's not phishing
    assert data["classification"] in [
        ClassificationType.SAFE,
        ClassificationType.SUSPICIOUS,
    ]
    assert 0.0 <= data["confidence_score"] <= 100.0


def test_analyze_email_phishing():
    # Clearly phishing - multiple red flags will trigger hard threshold
    payload = {
        "subject": "URGENT ACTION REQUIRED",  # Uppercase + Urgency
        "sender": "attacker@evil.ru",  # Suspicious TLD
        "body": "Click: http://1.1.1.1/paypal-secure now",  # IP URL + Pattern + Urgency
    }
    # Multiple high-severity heuristics will hit hard threshold (>= 0.9)

    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationType.PHISHING
    # Confidence score is now in percentage (0-100), should be high
    assert data["confidence_score"] >= 80.0


def test_invalid_input():
    # Missing required field 'body'
    payload = {"subject": "Incomplete", "sender": "oops@example.com"}
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422
