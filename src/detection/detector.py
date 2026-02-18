from detection.interface import DetectionModel, Resolver
from detection.parser import EmailParser
from models import EmailInput, ModelResult, ScanResult


class PhishingDetector:
    """
    Service for detecting phishing emails.
    Aggregates results from multiple detection models.
    """

    def __init__(
        self, parser: EmailParser, models: list[DetectionModel], resolver: Resolver
    ):
        self._parser = parser
        self._models = models
        self._resolver = resolver

    def scan(self, email_input: EmailInput) -> ScanResult:
        parsed_email = self._parser.parse(email_input)

        all_results: list[ModelResult] = []
        for model in self._models:
            result = model.classify(parsed_email)
            if result is not None:
                all_results.append(result)

        return self._resolver.resolve(all_results)
