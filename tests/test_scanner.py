from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file


TESTS_DIR = Path(__file__).resolve().parent


def test_command_injection_detected():
    file_path = TESTS_DIR / "vulnerable" / "command_injection.py"

    findings = analyze_python_file(str(file_path))

    assert any(
        finding["rule_id"] == "PY-CMD-001"
        for finding in findings
    )


def test_sql_injection_detected():
    file_path = TESTS_DIR / "vulnerable" / "sql_injection.py"

    findings = analyze_python_file(str(file_path))

    assert any(
        finding["rule_id"] == "PY-SQL-001"
        for finding in findings
    )