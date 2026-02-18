import pytest

from detection.classifiers.heuristics import HeuristicModel


@pytest.fixture
def model():
    return HeuristicModel()


def test_suspicious_tld(model, base_email):
    phishing_email = base_email.model_copy(update={"sender_domain": "example.xyz"})
    result = model._check_suspicious_tld(phishing_email)
    assert result.triggered
    assert result.rule_name == "Suspicious TLD"

    safe_email = base_email.model_copy(update={"sender_domain": "example.com"})
    result = model._check_suspicious_tld(safe_email)
    assert not result.triggered


def test_ip_url(model, base_email):
    phishing_email = base_email.model_copy(
        update={"urls": ["http://192.168.1.1/login"]}
    )
    result = model._check_ip_url(phishing_email)
    assert result.triggered
    assert result.rule_name == "IP-based URL"

    safe_email = base_email.model_copy(update={"urls": ["http://google.com"]})
    result = model._check_ip_url(safe_email)
    assert not result.triggered


def test_display_name_mismatch(model, base_email):
    phishing_email = base_email.model_copy(
        update={
            "display_name": "CEO <ceo@company.com>",
            "sender_email": "attacker@evil.com",
        }
    )
    result = model._check_display_name_mismatch(phishing_email)
    assert result.triggered

    valid_email = base_email.model_copy(
        update={
            "display_name": "User <user@valid.com>",
            "sender_email": "user@valid.com",
        }
    )
    result = model._check_display_name_mismatch(valid_email)
    assert not result.triggered

    named_email = base_email.model_copy(update={"display_name": "Just Name"})
    result = model._check_display_name_mismatch(named_email)
    assert not result.triggered


def test_urgency_keywords(model, base_email):
    phishing_email = base_email.model_copy(
        update={"normalized_body": "please verify account immediately"}
    )
    result = model._check_urgency_keywords(phishing_email)
    assert result.triggered

    safe_email = base_email.model_copy(update={"normalized_body": "take your time"})
    result = model._check_urgency_keywords(safe_email)
    assert not result.triggered


def test_uppercase_subject(model, base_email):
    phishing_email = base_email.model_copy(
        update={"subject": "URGENT ACTION REQUIRED NOW"}
    )
    result = model._check_uppercase_subject(phishing_email)
    assert result.triggered

    safe_email = base_email.model_copy(update={"subject": "Normal Subject Line"})
    result = model._check_uppercase_subject(safe_email)
    assert not result.triggered


def test_known_phishing_patterns(model, base_email):
    phishing_email = base_email.model_copy(
        update={"urls": ["http://paypal-secure-login.com"]}
    )
    result = model._check_known_phishing_patterns(phishing_email)
    assert result.triggered

    safe_email = base_email.model_copy(update={"urls": ["http://paypal.com"]})
    result = model._check_known_phishing_patterns(safe_email)
    assert not result.triggered


def test_multiple_links(model, base_email):
    phishing_email = base_email.model_copy(update={"urls": ["http://a.com"] * 6})
    result = model._check_multiple_links(phishing_email)
    assert result.triggered

    safe_email = base_email.model_copy(update={"urls": ["http://a.com"] * 5})
    result = model._check_multiple_links(safe_email)
    assert not result.triggered
