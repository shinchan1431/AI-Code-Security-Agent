from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file


def test_path_traversal_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "path_traversal.py"
    )

    findings = analyze_python_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "PY-PATH-001"
    assert findings[0]["type"] == "path_traversal"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 3
    assert "open()" in findings[0]["evidence"]


def test_safe_path_access_is_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "path_traversal_safe.py"
    )

    findings = analyze_python_file(str(fixture))

    assert findings == []
