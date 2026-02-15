from pydantic import BaseModel, Field


class EmailInput(BaseModel):
    subject: str
    sender: str
    body: str


class ParsedEmail(BaseModel):
    sender_email: str
    sender_domain: str
    display_name: str
    urls: list[str] = Field(default_factory=list)
    normalized_body: str
    subject: str
