from detection.interface import Resolver
from models import ClassificationType, ModelResult, ModelType, ScanResult


class HybridMLHeuristicResolver(Resolver):
    """
    Hybrid resolver that combines heuristic and ML model results.
    """

    def resolve(self, results: list[ModelResult]) -> ScanResult:
        """
        Resolve the classification based on the model results.
        """
        heuristic_result = next(
            (r for r in results if r.model_type == ModelType.HEURISTIC), None
        )
        if heuristic_result is None:
            raise ValueError("Heuristic result is required for hybrid resolution")
        ml_result = next((r for r in results if r.model_type == ModelType.ML), None)

        # ML model may be unavailable, so we fallback to heuristic result
        if ml_result is None:
            return ScanResult(
                classification=heuristic_result.classification,
                confidence_score=round(heuristic_result.confidence_score * 100, 2),
            )

        HARD_THRESHOLD = 0.9
        if heuristic_result.confidence_score >= HARD_THRESHOLD:
            return ScanResult(
                classification=ClassificationType.PHISHING,
                confidence_score=round(heuristic_result.confidence_score * 100, 2),
            )

        HEURISTIC_WEIGHT, ML_WEIGHT = 0.4, 0.6
        combined_score = (
            heuristic_result.confidence_score * HEURISTIC_WEIGHT
            + ml_result.confidence_score * ML_WEIGHT
        )

        classification = self._resolve_classification(combined_score)

        return ScanResult(
            classification=classification,
            confidence_score=round(combined_score * 100, 2),
        )

    def _resolve_classification(self, score: float) -> ClassificationType:
        """
        Internal resolution logic for hybrid resolver.
        """
        if score >= 0.75:
            return ClassificationType.PHISHING
        elif score >= 0.4:
            return ClassificationType.SUSPICIOUS
        else:
            return ClassificationType.SAFE
