from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_xss_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 4

    assert findings[0]["type"] == "xss"
    assert findings[0]["line"] == 3
    assert "innerHTML" in findings[0]["evidence"]

    assert findings[1]["type"] == "xss"
    assert findings[1]["line"] == 5
    assert "outerHTML" in findings[1]["evidence"]

    assert findings[2]["type"] == "xss"
    assert findings[2]["line"] == 7
    assert "insertAdjacentHTML" in findings[2]["evidence"]

    assert findings[3]["type"] == "xss"
    assert findings[3]["line"] == 9
    assert "document.write" in findings[3]["evidence"]


def test_safe_javascript_html_sinks_are_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_xss_derived_variable_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_derived.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 4
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_two_hop_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_two_hop.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_reassignment_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_reassignment.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5
    assert "innerHTML" in findings[0]["evidence"]
def test_safe_xss_reassignment_is_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_reassignment_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []

def test_javascript_xss_function_parameter_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_function_parameter.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 6
    assert "innerHTML" in findings[0]["evidence"]
