from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_sql_execute_detection():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_sql_vulnerable.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["type"] == "sql_injection"
    assert findings[0]["rule_id"] == "PY-SQL-001"
    assert findings[0]["line"] == 5
    assert "execute()" in findings[0]["evidence"]


def test_javascript_parameterized_sql_has_no_findings():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_sql_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []