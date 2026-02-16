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
    assert len(data["triggers"]) == 0


def test_analyze_email_phishing():
    # Use a high severity trigger (IP URL)
    payload = {
        "subject": "Urgent Action",
        "sender": "security@bank.com",
        "body": "Login here: http://10.0.0.1/verify",
    }
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == ClassificationType.PHISHING
    assert len(data["triggers"]) == 0


def test_invalid_input():
    # Missing required field 'body'
    payload = {"subject": "Incomplete", "sender": "oops@example.com"}
    response = client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 422
