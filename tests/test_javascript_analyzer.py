from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_eval_detection():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_vulnerable.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["type"] == "command_injection"
    assert findings[0]["line"] == 6
    assert "eval()" in findings[0]["evidence"]


def test_javascript_safe_code_has_no_findings():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []