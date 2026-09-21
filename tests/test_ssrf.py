from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file


def test_ssrf_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "ssrf.py"
    )

    findings = analyze_python_file(str(fixture))

    assert len(findings) == 1

    assert findings[0]["rule_id"] == "PY-SSRF-001"
    assert findings[0]["type"] == "ssrf"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 6
    assert "urlopen()" in findings[0]["evidence"]


def test_safe_urlopen_is_ignored():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "ssrf_safe.py"
    )

    findings = analyze_python_file(str(fixture))

    assert findings == []
