from pathlib import Path

from backend.scanner.javascript_analyzer import analyze_javascript_file


def test_javascript_child_process_exec_detection():
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "javascript_command_execution.js"
    )

    findings = analyze_javascript_file(str(fixture))

    assert len(findings) == 1
    assert findings[0]["type"] == "command_injection"
    assert findings[0]["line"] == 7
    assert "child_process" in findings[0]["evidence"]