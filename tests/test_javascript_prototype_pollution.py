from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_prototype_pollution_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "javascript_prototype_pollution.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 3

    assert findings[0]["type"] == "prototype_pollution"
    assert findings[0]["rule_id"] == "JS-PROT-001"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5

    assert findings[1]["type"] == "prototype_pollution"
    assert findings[1]["rule_id"] == "JS-PROT-001"
    assert findings[1]["severity"] == "HIGH"
    assert findings[1]["line"] == 7

    assert findings[2]["type"] == "prototype_pollution"
    assert findings[2]["rule_id"] == "JS-PROT-001"
    assert findings[2]["severity"] == "HIGH"
    assert findings[2]["line"] == 11
    
def test_javascript_safe_prototype_pollution_code():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_prototype_pollution_safe.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert findings == []