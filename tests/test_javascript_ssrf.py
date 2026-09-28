from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_ssrf_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_ssrf.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-SSRF-001"
    assert findings[0]["type"] == "ssrf"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 3


def test_javascript_ssrf_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_ssrf_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_ssrf_two_hop_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_ssrf_two_hop.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-SSRF-001"
    assert findings[0]["type"] == "ssrf"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 4
def test_javascript_ssrf_function_parameter_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_ssrf_function_parameter.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-SSRF-001"
    assert findings[0]["type"] == "ssrf"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 4