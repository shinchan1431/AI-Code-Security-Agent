from pathlib import Path
from backend.scanner.secret_analyzer import analyze_secrets

TESTS_DIR = Path(__file__).resolve().parent


def test_aws_access_key_detected():
    file_path = TESTS_DIR / "vulnerable" / "secrets.py"
    findings = analyze_secrets(str(file_path))

    assert any(
        finding["rule_id"] == "PY-SEC-001"
        for finding in findings
    )


def test_generic_api_key_detected():
    file_path = TESTS_DIR / "vulnerable" / "secrets.py"
    findings = analyze_secrets(str(file_path))

    assert any(
        "API Key" in finding["evidence"]
        for finding in findings
    )


def test_generic_secret_detected():
    file_path = TESTS_DIR / "vulnerable" / "secrets.py"
    findings = analyze_secrets(str(file_path))

    assert any(
        "Secret" in finding["evidence"]
        or "Password" in finding["evidence"]
        or "Token" in finding["evidence"]
        for finding in findings
    )
