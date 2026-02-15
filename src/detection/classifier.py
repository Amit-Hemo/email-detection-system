from models import ClassificationType, RuleResult, Severity


def classify_email(heuristics: list[RuleResult]) -> ClassificationType:
    """
    Aggregates heuristic results to determine the final classification.

    Logic:
    - Phishing: Any HIGH severity rule triggered.
    - Suspicious: 2 or more MEDIUM severity rules triggered.
    - Safe: Everything else.
    """

    high_severity_triggered = any(
        r.triggered and r.severity == Severity.HIGH for r in heuristics
    )
    medium_severity_count = sum(
        1 for r in heuristics if r.triggered and r.severity == Severity.MEDIUM
    )

    if high_severity_triggered:
        return ClassificationType.PHISHING

    if medium_severity_count >= 2:
        return ClassificationType.SUSPICIOUS

    return ClassificationType.SAFE
