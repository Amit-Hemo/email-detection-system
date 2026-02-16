import pytest

from detection.parser import EmailParser
from models import EmailInput


@pytest.fixture
def parser():
    return EmailParser()


def test_parse_email_valid_complex_sender(parser):
    email_input = EmailInput(
        subject="Test", sender="Test User <test@example.com>", body="Body"
    )
    result = parser.parse(email_input)
    assert result.sender_email == "test@example.com"
    assert result.display_name == "Test User"
    assert result.sender_domain == "example.com"


def test_parse_email_simple_sender(parser):
    email_input = EmailInput(subject="Test", sender="test@example.com", body="Body")
    result = parser.parse(email_input)
    assert result.sender_email == "test@example.com"
    assert result.display_name == ""


def test_parse_email_normalization(parser):
    email_input = EmailInput(
        subject="Test", sender="test@example.com", body="  This   is  UN-Normalized  "
    )
    result = parser.parse(email_input)
    assert result.normalized_body == "this is un-normalized"


def test_parse_email_malformed_sender_no_domain(parser):
    email_input = EmailInput(subject="Test", sender="malformed", body="Body")
    result = parser.parse(email_input)
    assert result.sender_email == "malformed"
    assert result.sender_domain == ""
