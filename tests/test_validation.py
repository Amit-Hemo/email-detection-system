import pytest
from pydantic import ValidationError

from models import EmailInput


def test_email_input_valid():
    """Verify valid input passes validation."""
    data = {
        "subject": "Test Subject",
        "sender": "test@example.com",
        "body": "This is a valid body.",
    }
    email = EmailInput(**data)
    assert email.subject == "Test Subject"


def test_email_input_empty_fields():
    """Verify empty strings fail validation (min_length=1)."""
    # Empty subject
    with pytest.raises(ValidationError):
        EmailInput(subject="", sender="user@test.com", body="Body")

    # Empty sender
    with pytest.raises(ValidationError):
        EmailInput(subject="Sub", sender="", body="Body")

    # Empty body
    with pytest.raises(ValidationError):
        EmailInput(subject="Sub", sender="user@test.com", body="")


def test_email_input_oversized_subject():
    """Verify oversized subject fails validation (max_length=1000)."""
    with pytest.raises(ValidationError):
        EmailInput(subject="A" * 1001, sender="user@test.com", body="Body")


def test_email_input_oversized_sender():
    """Verify oversized sender fails validation (max_length=500)."""
    with pytest.raises(ValidationError) as exc:
        EmailInput(subject="Sub", sender="a" * 501 + "@example.com", body="Body")
    assert "String should have at most 500 characters" in str(exc.value)


def test_email_input_oversized_body():
    """Verify oversized body fails validation (max_length=100,000)."""
    with pytest.raises(ValidationError) as exc:
        EmailInput(subject="Sub", sender="user@test.com", body="A" * 100_001)
    assert "String should have at most 100000 characters" in str(exc.value)


def test_email_input_exact_max_lengths():
    """Verify that exact maximum lengths are accepted."""
    EmailInput(subject="A" * 1000, sender="a" * 500, body="A" * 100_000)
    # No exception raised means success
