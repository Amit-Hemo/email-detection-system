import re

from models import ParsedEmail, RuleResult, Severity


def check_suspicious_tld(email: ParsedEmail) -> RuleResult:
    suspicious_tlds = {
        ".ru",
        ".xyz",
        ".top",
        ".work",
        ".info",
        ".cn",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
    }

    sender_domain = email.sender_domain.lower()
    triggered = any(sender_domain.endswith(tld) for tld in suspicious_tlds)

    return RuleResult(
        rule_name="Suspicious TLD",
        score=1.0 if triggered else 0.0,
        severity=Severity.HIGH,
        description=f"Sender domain '{sender_domain}' uses a suspicious TLD.",
        triggered=triggered,
    )


def check_ip_url(email: ParsedEmail) -> RuleResult:
    ip_pattern = r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

    triggered = False
    for url in email.urls:
        if re.search(ip_pattern, url):
            triggered = True
            break

    return RuleResult(
        rule_name="IP-based URL",
        score=1.0 if triggered else 0.0,
        severity=Severity.HIGH,
        description="Body contains a URL with an IP address instead of a domain.",
        triggered=triggered,
    )


def check_display_name_mismatch(email: ParsedEmail) -> RuleResult:
    display_name = email.display_name.lower()
    sender_email = email.sender_email.lower()

    email_in_display = re.search(r"[\w\.-]+@[\w\.-]+", display_name)

    triggered = False
    if email_in_display:
        found_email = email_in_display.group(0)
        if found_email != sender_email:
            triggered = True

    return RuleResult(
        rule_name="Display Name Mismatch",
        score=1.0 if triggered else 0.0,
        severity=Severity.HIGH,
        description="Display name contains an email address \
            and it is different from the sender address.",
        triggered=triggered,
    )


def check_urgency_keywords(email: ParsedEmail) -> RuleResult:
    keywords = {
        "urgent",
        "immediate",
        "immediately",
        "verify account",
        "unauthorized",
        "suspended",
        "action required",
        "locked",
        "now",
    }

    body = email.normalized_body
    subject = email.subject.lower()

    triggered = any(keyword in body or keyword in subject for keyword in keywords)

    return RuleResult(
        rule_name="Urgency Keywords",
        score=0.5 if triggered else 0.0,
        severity=Severity.MEDIUM,
        description="Content contains urgent or threatening language.",
        triggered=triggered,
    )


def check_uppercase_subject(email: ParsedEmail) -> RuleResult:
    subject = email.subject
    if len(subject) < 10:
        triggered = False
    else:
        upper_count = sum(1 for c in subject if c.isupper())
        triggered = (upper_count / len(subject)) > 0.5

    return RuleResult(
        rule_name="Excessive Uppercase Subject",
        score=0.3 if triggered else 0.0,
        severity=Severity.MEDIUM,
        description="Subject line contains excessive uppercase characters.",
        triggered=triggered,
    )


def check_known_phishing_patterns(email: ParsedEmail) -> RuleResult:
    patterns = {"paypal-secure", "apple-id-verify", "bank-login", "account-alert"}

    triggered = False
    for url in email.urls:
        if any(pattern in url.lower() for pattern in patterns):
            triggered = True
            break

    return RuleResult(
        rule_name="Known Phishing Patterns",
        score=1.0 if triggered else 0.0,
        severity=Severity.HIGH,
        description="Content contains known phishing URL patterns.",
        triggered=triggered,
    )


def check_multiple_links(email: ParsedEmail) -> RuleResult:
    link_count = len(email.urls)
    triggered = link_count > 5

    return RuleResult(
        rule_name="Multiple External Links",
        score=0.2 if triggered else 0.0,
        severity=Severity.LOW,
        description=f"Email contains a high number of external links ({link_count}).",
        triggered=triggered,
    )


def analyze_heuristics(email: ParsedEmail) -> list[RuleResult]:
    """
    Runs all heuristic rules against the parsed email.
    """
    rules = [
        check_suspicious_tld,
        check_ip_url,
        check_display_name_mismatch,
        check_urgency_keywords,
        check_uppercase_subject,
        check_known_phishing_patterns,
        check_multiple_links,
    ]

    return [rule(email) for rule in rules]
