from pathlib import Path

from backend.scanner.ast_analyzer import analyze_python_file


def test_weak_crypto_detection():
    fixture = (
        Path(__file__).parent
        / "vulnerable"
        / "weak_crypto.py"
    )

    findings = analyze_python_file(str(fixture))

    assert len(findings) == 2

    assert findings[0]["rule_id"] == "PY-CRYPTO-001"
    assert findings[0]["type"] == "weak_cryptography"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["line"] == 5
    assert "hashlib.md5" in findings[0]["evidence"]

    assert findings[1]["rule_id"] == "PY-CRYPTO-001"
    assert findings[1]["type"] == "weak_cryptography"
    assert findings[1]["severity"] == "MEDIUM"
    assert findings[1]["line"] == 7
    assert "hashlib.sha1" in findings[1]["evidence"]
