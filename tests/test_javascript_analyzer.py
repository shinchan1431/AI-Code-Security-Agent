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
def test_javascript_xss_function_return_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_return.js"
    )

    findings = analyze_javascript_file(str(fixture))

    xss_findings = [
        finding
        for finding in findings
        if finding["rule_id"] == "JS-XSS-001"
    ]

    assert len(xss_findings) == 1
    assert xss_findings[0]["type"] == "xss"
    assert xss_findings[0]["severity"] == "HIGH"
    assert xss_findings[0]["line"] == 9


def test_javascript_xss_function_return_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_function_return_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []