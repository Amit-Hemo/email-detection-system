import re

from models import EmailInput, ParsedEmail


def extract_sender_info(sender_str: str) -> tuple[str, str, str]:
    """
    Extracts display name, email address, and domain from a sender string.
    Supported formats:
    - "Name <email@domain.com>"
    - "email@domain.com"
    """
    # Regex for "Name <email>" format
    match = re.match(r"(.*)<(.+)>", sender_str)
    if match:
        display_name = match.group(1).strip().strip('"')
        email = match.group(2).strip()
    else:
        display_name = ""
        email = sender_str.strip()

    # Extract domain
    if "@" in email:
        domain = email.split("@")[-1]
    else:
        domain = ""

    return display_name, email, domain


def extract_urls(text: str) -> list[str]:
    """
    Extracts URLs from text using regex.
    """
    url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
    return re.findall(url_pattern, text)


def normalize_text(text: str) -> str:
    """
    Normalizes text by lowercasing and removing excessive whitespace.
    """
    return " ".join(text.lower().split())


def parse_email(data: EmailInput) -> ParsedEmail:
    """
    Parses a raw email input into a structured object for analysis.
    """
    display_name, sender_email, sender_domain = extract_sender_info(data.sender)
    urls = extract_urls(data.body)
    normalized_body = normalize_text(data.body)

    return ParsedEmail(
        sender_email=sender_email,
        sender_domain=sender_domain,
        display_name=display_name,
        urls=urls,
        normalized_body=normalized_body,
        subject=data.subject,
    )
