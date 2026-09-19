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
    