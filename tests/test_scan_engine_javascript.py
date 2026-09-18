from pathlib import Path

from backend.scanner.scan_engine import scan_repository


def test_scan_engine_detects_javascript_eval(tmp_path):
    repository = tmp_path / "javascript_repo"
    repository.mkdir()

    javascript_file = repository / "app.js"
    javascript_file.write_text(
        """
const userInput = "console.log('hello')";
eval(userInput);
""",
        encoding="utf-8",
    )

    result = scan_repository(str(repository))

    assert result.status == "completed"
    assert result.summary.files_found == 1
    assert result.summary.files_scanned == 1
    assert result.summary.findings == 1

    finding = result.findings[0]

    assert finding["file"] == "app.js"
    assert finding["type"] == "command_injection"
    assert finding["line"] == 3
    assert "eval()" in finding["evidence"]