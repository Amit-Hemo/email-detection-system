import pytest

from detection.classifiers.ml import MLModel
from models import ClassificationType, ModelType, ParsedEmail


@pytest.fixture
def base_email():
    """Base email for testing ML model."""
    return ParsedEmail(
        sender_email="test@example.com",
        sender_domain="example.com",
        display_name="Test User",
        urls=[],
        normalized_body="this is a normal email body",
        subject="Normal Subject",
    )


class TestMLModelAvailability:
    """Test ML model availability and graceful degradation."""

    def test_model_returns_none_when_unavailable(self, monkeypatch, base_email):
        """When model file is missing, classify should return None."""

        def mock_load_fail(*args, **kwargs):
            raise FileNotFoundError("Model file not found")

        monkeypatch.setattr("joblib.load", mock_load_fail)

        model = MLModel()
        result = model.classify(base_email)

        assert result is None

    def test_model_availability_flag_when_load_fails(self, monkeypatch):
        """When model fails to load, _available should be False."""

        def mock_load_fail(*args, **kwargs):
            raise Exception("Model load error")

        monkeypatch.setattr("joblib.load", mock_load_fail)

        model = MLModel()
        assert model._available is False


class TestMLModelTextCombination:
    """Test text preprocessing for ML model."""

    def test_build_text_combined_format(self):
        """Verify text combination matches training format."""
        model = MLModel()
        email = ParsedEmail(
            sender_email="sender@test.com",
            sender_domain="test.com",
            display_name="Sender",
            urls=[],
            normalized_body="email body content",
            subject="Email Subject",
        )

        combined = model._build_text_combined(email)

        # Format should be: "{subject} {sender_email} {normalized_body}"
        expected = "Email Subject sender@test.com email body content"
        assert combined == expected

    def test_build_text_combined_with_special_chars(self):
        """Test text combination with special characters."""
        model = MLModel()
        email = ParsedEmail(
            sender_email="user+tag@example.com",
            sender_domain="example.com",
            display_name="User",
            urls=[],
            normalized_body="verify account immediately!",
            subject="URGENT: Action Required",
        )

        combined = model._build_text_combined(email)

        expected = (
            "URGENT: Action Required user+tag@example.com verify account immediately!"
        )
        assert combined == expected


class TestMLModelClassification:
    """Test ML model classification logic."""

    def test_resolve_classification_phishing_threshold(self):
        """Score >= 0.7 should return PHISHING."""
        model = MLModel()

        assert model._resolve_classification(0.7) == ClassificationType.PHISHING
        assert model._resolve_classification(0.85) == ClassificationType.PHISHING
        assert model._resolve_classification(1.0) == ClassificationType.PHISHING

    def test_resolve_classification_suspicious_threshold(self):
        """Score between 0.3 and 0.7 should return SUSPICIOUS."""
        model = MLModel()

        assert model._resolve_classification(0.3) == ClassificationType.SUSPICIOUS
        assert model._resolve_classification(0.5) == ClassificationType.SUSPICIOUS
        assert model._resolve_classification(0.69) == ClassificationType.SUSPICIOUS

    def test_resolve_classification_safe_threshold(self):
        """Score < 0.3 should return SAFE."""
        model = MLModel()

        assert model._resolve_classification(0.0) == ClassificationType.SAFE
        assert model._resolve_classification(0.15) == ClassificationType.SAFE
        assert model._resolve_classification(0.29) == ClassificationType.SAFE


class TestMLModelIntegration:
    """Test full ML model classification with mocked predictions."""

    def test_classify_returns_model_result_structure(self, monkeypatch, base_email):
        """Verify classify returns correct ModelResult structure."""

        def mock_predict_proba(self, texts):
            return [[0.8, 0.2]]  # Low phishing probability

        # Mock successful model load
        monkeypatch.setattr("joblib.load", lambda *args: None)
        # Mock predict_proba
        monkeypatch.setattr(
            "detection.classifiers.ml.MLModel._model_predict", lambda self, text: 0.2
        )

        model = MLModel()
        result = model.classify(base_email)

        assert result is not None
        assert result.classification == ClassificationType.SAFE
        assert result.confidence_score == 0.2
        assert result.model_type == ModelType.ML

    def test_classify_phishing_high_probability(self, monkeypatch, base_email):
        """High phishing probability should classify as PHISHING."""
        monkeypatch.setattr("joblib.load", lambda *args: None)
        monkeypatch.setattr(
            "detection.classifiers.ml.MLModel._model_predict", lambda self, text: 0.95
        )

        model = MLModel()
        base_email.subject = "URGENT: Verify your account"
        base_email.normalized_body = "click here immediately to verify"
        result = model.classify(base_email)

        assert result.classification == ClassificationType.PHISHING
        assert result.confidence_score == 0.95

    def test_classify_suspicious_medium_probability(self, monkeypatch, base_email):
        """Medium phishing probability should classify as SUSPICIOUS."""
        monkeypatch.setattr("joblib.load", lambda *args: None)
        monkeypatch.setattr(
            "detection.classifiers.ml.MLModel._model_predict", lambda self, text: 0.5
        )

        model = MLModel()
        result = model.classify(base_email)

        assert result.classification == ClassificationType.SUSPICIOUS
        assert result.confidence_score == 0.5
