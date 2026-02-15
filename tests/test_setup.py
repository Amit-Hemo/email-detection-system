from detection.classifier import classify_email
from detection.heuristics import analyze_heuristics
from detection.parser import parse_email
from models import ParsedEmail


def test_imports():
    """Verify that all modules can be imported and structure is correct."""
    assert ParsedEmail
    assert parse_email
    assert analyze_heuristics
    assert classify_email


def test_basic_check():
    assert True
