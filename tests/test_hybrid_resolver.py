import pytest

from detection.resolver import HybridMLHeuristicResolver
from models import ClassificationType, ModelResult, ModelType


@pytest.fixture
def resolver():
    """Create a HybridMLHeuristicResolver instance."""
    return HybridMLHeuristicResolver()


class TestMLUnavailableFallback:
    """Test fallback to heuristics when ML model is unavailable."""

    def test_fallback_to_heuristics_when_ml_none(self, resolver):
        """When ML result is None, should use only heuristics."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.8,
            model_type=ModelType.HEURISTIC,
        )

        results = [heuristic_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.PHISHING
        assert scan_result.confidence_score == 80.0  # Converted to percentage

    def test_fallback_preserves_heuristic_classification(self, resolver):
        """All heuristic classifications should be preserved when ML unavailable."""
        test_cases = [
            (ClassificationType.SAFE, 0.1),
            (ClassificationType.SUSPICIOUS, 0.5),
            (ClassificationType.PHISHING, 0.9),
        ]

        for expected_class, score in test_cases:
            heuristic_result = ModelResult(
                classification=expected_class,
                confidence_score=score,
                model_type=ModelType.HEURISTIC,
            )
            results = [heuristic_result]
            scan_result = resolver.resolve(results)

            assert scan_result.classification == expected_class
            assert scan_result.confidence_score == round(score * 100, 2)


class TestHardThresholdBypass:
    """Test hard threshold bypass at heuristics >= 0.9."""

    def test_hard_threshold_exactly_at_090(self, resolver):
        """Heuristics at 0.9 should bypass ML and classify as PHISHING."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.9,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.1,  # Low ML score should be ignored
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.PHISHING
        assert scan_result.confidence_score == 90.0

    def test_hard_threshold_above_090(self, resolver):
        """Heuristics > 0.9 should bypass ML."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.95,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.05,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.PHISHING
        assert scan_result.confidence_score == 95.0

    def test_hard_threshold_just_below_090(self, resolver):
        """Heuristics = 0.89 should NOT bypass ML, use weighted combination."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.89,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.1,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.89 * 0.4 + 0.1 * 0.6 = 0.356 + 0.06 = 0.416
        # Should be SUSPICIOUS (0.4 <= 0.416 < 0.75)
        assert scan_result.classification == ClassificationType.SUSPICIOUS
        expected_score = round((0.89 * 0.4 + 0.1 * 0.6) * 100, 2)
        assert scan_result.confidence_score == expected_score


class TestWeightedCombination:
    """Test weighted combination of heuristics (40%) and ML (60%)."""

    def test_weighted_combination_calculation(self, resolver):
        """Verify correct weighted average calculation."""
        heuristic_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.5,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.6,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.5 * 0.4 + 0.6 * 0.6 = 0.2 + 0.36 = 0.56
        expected_score = round((0.5 * 0.4 + 0.6 * 0.6) * 100, 2)
        assert scan_result.confidence_score == expected_score
        assert scan_result.classification == ClassificationType.SUSPICIOUS

    def test_high_heuristics_low_ml_below_threshold(self, resolver):
        """High heuristics (0.85) + low ML (0.2) below 0.9 threshold."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.85,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.2,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.85 * 0.4 + 0.2 * 0.6 = 0.34 + 0.12 = 0.46
        # Should be SUSPICIOUS (0.4 <= 0.46 < 0.75)
        assert scan_result.classification == ClassificationType.SUSPICIOUS

    def test_low_heuristics_high_ml(self, resolver):
        """Low heuristics (0.3) + high ML (0.8) weighted combination."""
        heuristic_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.3,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.8,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.3 * 0.4 + 0.8 * 0.6 = 0.12 + 0.48 = 0.6
        # Should be SUSPICIOUS (0.4 <= 0.6 < 0.75)
        assert scan_result.classification == ClassificationType.SUSPICIOUS
        expected_score = round(0.6 * 100, 2)
        assert scan_result.confidence_score == expected_score


class TestClassificationBoundaries:
    """Test classification boundaries with weighted combinations."""

    def test_boundary_safe_to_suspicious_at_040(self, resolver):
        """Combined score at exactly 0.4 should be SUSPICIOUS."""
        # Need: 0.4 * h + 0.6 * m = 0.4
        # Example: h=0.4, m=0.4 -> 0.16 + 0.24 = 0.4
        heuristic_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.4,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.4,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.SUSPICIOUS

    def test_boundary_just_below_040(self, resolver):
        """Combined score < 0.4 should be SAFE."""
        # h=0.3, m=0.3 -> 0.12 + 0.18 = 0.3 < 0.4
        heuristic_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.3,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SUSPICIOUS,
            confidence_score=0.3,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.SAFE

    def test_boundary_suspicious_to_phishing_at_075(self, resolver):
        """Combined score at exactly 0.75 should be PHISHING."""
        # Need: 0.4 * h + 0.6 * m = 0.75
        # Example: h=0.75, m=0.75 -> 0.3 + 0.45 = 0.75
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.75,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.75,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.PHISHING

    def test_boundary_just_below_075(self, resolver):
        """Combined score < 0.75 should be SUSPICIOUS."""
        # h=0.7, m=0.7 -> 0.28 + 0.42 = 0.7 < 0.75
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.7,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.7,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        assert scan_result.classification == ClassificationType.SUSPICIOUS


class TestModelDisagreement:
    """Test scenarios where models disagree."""

    def test_both_models_low_scores(self, resolver):
        """Both models return low scores -> SAFE."""
        heuristic_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.1,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.15,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.1 * 0.4 + 0.15 * 0.6 = 0.04 + 0.09 = 0.13
        assert scan_result.classification == ClassificationType.SAFE

    def test_both_models_high_scores(self, resolver):
        """Both models return high scores -> PHISHING."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.85,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.8,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.85 * 0.4 + 0.8 * 0.6 = 0.34 + 0.48 = 0.82
        assert scan_result.classification == ClassificationType.PHISHING

    def test_extreme_disagreement_high_heuristics_low_ml(self, resolver):
        """Heuristics says PHISHING (0.95), ML says SAFE (0.05)."""
        heuristic_result = ModelResult(
            classification=ClassificationType.PHISHING,
            confidence_score=0.95,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.05,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Hard threshold at 0.9 should bypass ML
        assert scan_result.classification == ClassificationType.PHISHING
        assert scan_result.confidence_score == 95.0


class TestConfidenceScoreConversion:
    """Test confidence score conversion to percentage and rounding."""

    def test_score_converted_to_percentage(self, resolver):
        """Scores should be converted from 0.0-1.0 to 0.0-100.0."""
        heuristic_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.5,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.5,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.5 * 0.4 + 0.5 * 0.6 = 0.5
        assert scan_result.confidence_score == 50.0

    def test_score_rounded_to_two_decimals(self, resolver):
        """Scores should be rounded to 2 decimal places."""
        heuristic_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.123456,
            model_type=ModelType.HEURISTIC,
        )
        ml_result = ModelResult(
            classification=ClassificationType.SAFE,
            confidence_score=0.654321,
            model_type=ModelType.ML,
        )

        results = [heuristic_result, ml_result]
        scan_result = resolver.resolve(results)

        # Combined: 0.123456 * 0.4 + 0.654321 * 0.6 = 0.0493824 + 0.3925926 = 0.441975
        expected = round(0.441975 * 100, 2)
        assert scan_result.confidence_score == expected
        assert scan_result.confidence_score == 44.2
