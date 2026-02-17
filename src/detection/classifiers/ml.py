import joblib

from detection.interface import DetectionModel
from models import ClassificationType, ModelResult, ModelType, ParsedEmail
from utils import get_project_root

FILE_NAME = "phishing_detector_v1.pkl"


class MLModel(DetectionModel):
    def __init__(self):
        try:
            self._model_pipeline = joblib.load(get_project_root() / "ml" / FILE_NAME)
            self._available = True
        except Exception:
            self._available = False

    def classify(self, email: ParsedEmail) -> ModelResult | None:
        """
        Classify the email as phishing, suspicious, or safe.
        """
        if not self._available:
            return None

        phishing_probability = self._model_predict(self._build_text_combined(email))

        return ModelResult(
            classification=self._resolve_classification(phishing_probability),
            confidence_score=phishing_probability,
            model_type=ModelType.ML,
        )

    def _build_text_combined(self, email: ParsedEmail) -> str:
        """
        Build a combined text from the email fields to match the training data format.
        """
        return f"{email.subject} {email.sender_email} {email.normalized_body}"

    def _model_predict(self, text: str) -> float:
        """
        Predict the probability of the email being phishing.
        """
        return float(self._model_pipeline.predict_proba([text])[0][1])

    def _resolve_classification(self, score: float) -> ClassificationType:
        """
        Resolve the classification based on the probability score.
        """
        if score >= 0.7:
            return ClassificationType.PHISHING
        elif score >= 0.3:
            return ClassificationType.SUSPICIOUS
        else:
            return ClassificationType.SAFE
