from dataclasses import dataclass


@dataclass
class ParsedEmail:
    sender_email: str
    sender_domain: str
    display_name: str
    urls: list[str]
    normalized_body: str
    # Add other fields as needed
