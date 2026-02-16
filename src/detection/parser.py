import re

from models import EmailInput, ParsedEmail


class EmailParser:
    """
    Parses raw email input into a structured object for analysis.
    """

    def parse(self, data: EmailInput) -> ParsedEmail:
        display_name, sender_email, sender_domain = self._extract_sender_info(
            data.sender
        )
        urls = self._extract_urls(data.body)
        normalized_body = self._normalize_text(data.body)

        return ParsedEmail(
            sender_email=sender_email,
            sender_domain=sender_domain,
            display_name=display_name,
            urls=urls,
            normalized_body=normalized_body,
            subject=data.subject,
        )

    def _extract_sender_info(self, sender_str: str) -> tuple[str, str, str]:
        """
        Extracts display name, email address, and domain from a sender string.
        """
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

    def _extract_urls(self, text: str) -> list[str]:
        """
        Extracts URLs from text using regex.
        """
        url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*"
        return re.findall(url_pattern, text)

    def _normalize_text(self, text: str) -> str:
        """
        Normalizes text by lowercasing and removing excessive whitespace.
        """
        return " ".join(text.lower().split())
