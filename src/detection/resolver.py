from detection.interface import Resolver
from models import ModelResult, ScanResult


class SimpleResolver(Resolver):
    """
    Simple implementation of a resolver that aggregates model results.
    Currently, it just takes the classification from the first model (Heuristic).
    In the future, it can implement voting logic (e.g. Heuristic vs ML).
    """

    def resolve(self, results: list[ModelResult]) -> ScanResult:
        if not results:
            # Realistically should not happen if config is correct
            from models import ClassificationType

            return ScanResult(classification=ClassificationType.SAFE)

        # For now, just take the first heuristic result until we have more models
        primary_result = results[0]

        return ScanResult(
            classification=primary_result.classification,
            triggers=[],
        )
