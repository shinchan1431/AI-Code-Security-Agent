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

def test_javascript_xss_function_parameter_derived_variable_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_parameter_derived.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["type"] == "xss"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 7
    assert "innerHTML" in findings[0]["evidence"]
def test_javascript_xss_function_return_safe_value():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_function_return_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 0
def test_javascript_xss_function_return_transform_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_return_transform.js"
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


def test_javascript_xss_function_return_transform_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_function_return_transform_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []

def test_javascript_xss_object_property():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "xss_object_property.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "JS-XSS-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 7
def test_javascript_xss_object_property_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "xss_object_property_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_xss_function_return_object_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_function_return_object.js"
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
    assert xss_findings[0]["line"] == 11


def test_javascript_xss_function_return_object_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_function_return_object_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_xss_object_property_function_argument_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_property_function_arg.js"
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
    assert xss_findings[0]["line"] == 8


def test_javascript_xss_object_property_function_argument_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_property_function_arg_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []
def test_javascript_xss_object_alias_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_xss_object_alias.js"
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


def test_javascript_xss_object_alias_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_xss_object_alias_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []