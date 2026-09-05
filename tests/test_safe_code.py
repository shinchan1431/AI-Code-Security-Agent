from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file
from backend.scanner.secret_analyzer import analyze_secrets

TESTS_DIR = Path(__file__).resolve().parent


def test_safe_python_has_no_ast_findings():
    file_path = TESTS_DIR / "safe.py"
    findings = analyze_python_file(str(file_path))

    assert findings == []


def test_safe_python_has_no_secret_findings():
    file_path = TESTS_DIR / "safe.py"
    findings = analyze_secrets(str(file_path))

    assert findings == []
