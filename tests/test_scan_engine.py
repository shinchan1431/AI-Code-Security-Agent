from pathlib import Path

from backend.scanner.scan_engine import scan_repository

TESTS_DIR = Path(__file__).resolve().parent


def test_scan_vulnerable_repository():
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    assert result.status == "completed"
    assert result.summary.files_scanned > 0
    assert result.summary.findings > 0


def test_scan_vulnerable_repository_detects_command_injection():
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    assert any(
        finding["rule_id"] == "PY-CMD-001"
        for finding in result.findings
    )


def test_scan_vulnerable_repository_detects_sql_injection():
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    assert any(
        finding["rule_id"] == "PY-SQL-001"
        for finding in result.findings
    )


def test_scan_safe_repository():
    repository_path = TESTS_DIR
    result = scan_repository(str(repository_path))

    assert result.status == "completed"
    assert result.summary.files_scanned > 0
def test_finding_paths_are_repository_relative():
    repository_path = TESTS_DIR / "vulnerable"
    result = scan_repository(str(repository_path))

    assert result.status == "completed"
    assert result.findings

    for finding in result.findings:
        file_path = finding["file"]

        assert not Path(file_path).is_absolute()