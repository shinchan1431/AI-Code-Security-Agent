from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_path_traversal_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_path_traversal.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "JS-PATH-001"
    assert findings[0]["type"] == "path_traversal"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 3


def test_javascript_path_traversal_safe():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_path_traversal_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []