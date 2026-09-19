from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file


def test_insecure_deserialization_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "insecure_deserialization.py"
    )

    findings = analyze_python_file(str(fixture))

    assert len(findings) == 2

    assert findings[0]["rule_id"] == "PY-SEC-002"
    assert findings[0]["type"] == "insecure_deserialization"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["line"] == 5
    assert "pickle.loads" in findings[0]["evidence"]

    assert findings[1]["rule_id"] == "PY-SEC-002"
    assert findings[1]["type"] == "insecure_deserialization"
    assert findings[1]["severity"] == "HIGH"
    assert findings[1]["line"] == 8
    assert "pickle.load" in findings[1]["evidence"]