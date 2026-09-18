from pathlib import Path

from backend.scanner.scan_engine import scan_repository


def test_scan_engine_detects_javascript_hardcoded_secret(tmp_path):
    repository = tmp_path / "javascript_secret_repo"
    repository.mkdir()

    javascript_file = repository / "config.js"
    javascript_file.write_text(
        """
const apiKey = "1234567890abcdef";
const password = "supersecret123";
""",
        encoding="utf-8",
    )

    result = scan_repository(str(repository))

    assert result.status == "completed"
    assert result.summary.files_found == 1
    assert result.summary.files_scanned == 1
    assert result.summary.findings == 2

    finding_types = {
        finding["type"]
        for finding in result.findings
    }

    assert "hardcoded_secret" in finding_types