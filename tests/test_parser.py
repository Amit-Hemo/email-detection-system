from detection.parser import parse_email
from models import EmailInput


def test_parse_email_valid_complex_sender():
    input_data = EmailInput(
        sender="Amazon <admin@amazon.com>",
        subject="Your Order",
        body="Please check your order at https://amazon.com/order and http://tracking.com",
    )
    result = parse_email(input_data)

    assert result.sender_email == "admin@amazon.com"
    assert result.sender_domain == "amazon.com"
    assert result.display_name == "Amazon"
    assert result.subject == "Your Order"
    assert "https://amazon.com/order" in result.urls
    assert "http://tracking.com" in result.urls
    assert len(result.urls) == 2
    assert (
        result.normalized_body
        == "please check your order at https://amazon.com/order and http://tracking.com"
    )


def test_parse_email_simple_sender():
    input_data = EmailInput(
        sender="support@google.com", subject="Help", body="Hello world"
    )
    result = parse_email(input_data)

    assert result.sender_email == "support@google.com"
    assert result.sender_domain == "google.com"
    assert result.display_name == ""
    assert len(result.urls) == 0
    assert result.normalized_body == "hello world"


def test_parse_email_normalization():
    input_data = EmailInput(
        sender="test@test.com", subject="Test", body="  This   IS  a   TEST  "
    )
    result = parse_email(input_data)

    assert result.normalized_body == "this is a test"


def test_parse_email_malformed_sender_no_domain():
    input_data = EmailInput(sender="invalid-email", subject="Test", body="Body")
    result = parse_email(input_data)

    assert result.sender_email == "invalid-email"
    assert result.sender_domain == ""
