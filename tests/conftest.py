import pytest

from models import ParsedEmail


@pytest.fixture
def base_email():
    """Shared base email fixture for testing."""
    return ParsedEmail(
        sender_email="test@example.com",
        sender_domain="example.com",
        display_name="Test User",
        urls=[],
        normalized_body="this is a normal email body",
        subject="Normal Subject",
    )
