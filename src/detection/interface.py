from abc import ABC, abstractmethod

from models import ModelResult, ParsedEmail, ScanResult


class DetectionModel(ABC):
    """
    Interface for detection models.
    """

    @abstractmethod
    def classify(self, email: ParsedEmail) -> ModelResult:
        """
        Classifies the parsed email.
        """
        pass


class Resolver(ABC):
    """
    Interface for resolving final classification from multiple model results.
    """

    @abstractmethod
    def resolve(self, results: list[ModelResult]) -> ScanResult:
        """
        Resolves the final ScanResult.
        """
        pass
