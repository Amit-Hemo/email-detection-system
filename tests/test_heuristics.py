import pytest

from detection.classifiers.heuristics import HeuristicModel
from models import ParsedEmail


@pytest.fixture
def base_email():
    return ParsedEmail(
        sender_email="test@example.com",
        sender_domain="example.com",
        display_name="Test User",
        urls=[],
        normalized_body="this is a normal email body",
        subject="Normal Subject",
    )


@pytest.fixture
def model():
    return HeuristicModel()


def test_suspicious_tld(model, base_email):
    base_email.sender_domain = "example.xyz"
    result = model._check_suspicious_tld(base_email)
    assert result.triggered
    assert result.rule_name == "Suspicious TLD"

    base_email.sender_domain = "example.com"
    result = model._check_suspicious_tld(base_email)
    assert not result.triggered


def test_ip_url(model, base_email):
    base_email.urls = ["http://192.168.1.1/login"]
    result = model._check_ip_url(base_email)
    assert result.triggered
    assert result.rule_name == "IP-based URL"

    base_email.urls = ["http://google.com"]
    result = model._check_ip_url(base_email)
    assert not result.triggered


def test_display_name_mismatch(model, base_email):
    base_email.display_name = "CEO <ceo@company.com>"
    base_email.sender_email = "attacker@evil.com"
    result = model._check_display_name_mismatch(base_email)
    assert result.triggered

    base_email.display_name = "User <user@valid.com>"
    base_email.sender_email = "user@valid.com"
    result = model._check_display_name_mismatch(base_email)
    assert not result.triggered

    base_email.display_name = "Just Name"
    result = model._check_display_name_mismatch(base_email)
    assert not result.triggered


def test_urgency_keywords(model, base_email):
    base_email.normalized_body = "please verify account immediately"
    result = model._check_urgency_keywords(base_email)
    assert result.triggered

    base_email.normalized_body = "take your time"
    result = model._check_urgency_keywords(base_email)
    assert not result.triggered


def test_uppercase_subject(model, base_email):
    base_email.subject = "URGENT ACTION REQUIRED NOW"
    result = model._check_uppercase_subject(base_email)
    assert result.triggered

    base_email.subject = "Normal Subject Line"
    result = model._check_uppercase_subject(base_email)
    assert not result.triggered


def test_known_phishing_patterns(model, base_email):
    base_email.urls = ["http://paypal-secure-login.com"]
    result = model._check_known_phishing_patterns(base_email)
    assert result.triggered

    base_email.urls = ["http://paypal.com"]
    result = model._check_known_phishing_patterns(base_email)
    assert not result.triggered


def test_multiple_links(model, base_email):
    base_email.urls = ["http://a.com"] * 6
    result = model._check_multiple_links(base_email)
    assert result.triggered

    base_email.urls = ["http://a.com"] * 5
    result = model._check_multiple_links(base_email)
    assert not result.triggered
